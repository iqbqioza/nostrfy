# nostrfy Configuration Reference

This page is the complete reference for the `nostrfy.toml` configuration file: every key, its type, its default, and exactly what it does.

## Table of Contents

1. [Basics](#1-basics)
2. [Configuration Sections](#2-configuration-sections)
3. [`[relay]` — relay identity](#3-relay--relay-identity)
4. [`[server]` — server settings](#4-server--server-settings)
5. [`[limits]` — limits and protections](#5-limits--limits-and-protections)
6. [`[database]` — database settings](#6-database--database-settings)
7. [`[daemon]` — daemon settings](#7-daemon--daemon-settings)
8. [`[access]` — access control](#8-access--access-control)
9. [Validation rules](#9-validation-rules)
10. [Reloading at runtime (SIGHUP)](#10-reloading-at-runtime-sighup)
11. [Full example](#11-full-example)
12. [Common mistakes](#12-common-mistakes)

---

## 1. Basics

The configuration is a [TOML](https://toml.io/) file, by default named `nostrfy.toml`.

**Create** it with:

```bash
./target/release/nostrfy --config nostrfy.toml init
```

**Validate** it (recommended before every start):

```bash
./target/release/nostrfy --config nostrfy.toml check
```

Every command takes `--config <path>` (default `nostrfy.toml`).

### General syntax

```toml
[section]          # a section header
key = "string"     # string value
key = 8080         # integer value
key = [1, 2]       # array of integers
key = []           # empty array
key = true         # boolean
```

---

## 2. Configuration Sections

| Section | Purpose |
| --- | --- |
| `[relay]` | Identity, URLs and NIP toggles |
| `[server]` | Network binding, API split, metrics |
| `[rpc]` | NIP-86 management RPC (port, auth, body limit) |
| `[limits]` | All limits and overload protections |
| `[database]` | LMDB storage, DB thread timeouts and queue caps, search index |
| `[daemon]` | PID/log/stats files and rotation |
| `[access]` | Initial access control lists (also changeable at runtime) |
| `[blossom]` | Blossom file server (media hosting) |

Every key is optional; a missing key uses the default shown below.

---

## 3. `[relay]` — relay identity

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | `"nostrfy"` | Relay name (shown to clients via NIP-11) |
| `description` | string | `"A minimal and stable Nostr relay"` | Relay description (NIP-11) |
| `pubkey` | string (64 hex) | `""` | Administrator public key (NIP-11 `pubkey` field) |
| `contact` | string | `""` | Administrator contact (URI, e.g. `mailto:` or `https://`) |
| `icon` | string | `""` | Relay icon image URL |
| `post_policy` | string | `""` | URL pointing to the relay's posting policy |
| `private_key` | string (64 hex) | `""` | The relay's own secret key; required for NIP-29 groups |
| `public_url` | string | `""` | The relay's public URL (e.g. `wss://relay.example.com`) |
| `livekit_url` | string | `""` | LiveKit server URL for NIP-29 audio/video rooms |
| `livekit_api_key` | string | `""` | LiveKit API key |
| `livekit_api_secret` | string | `""` | LiveKit API secret (used to sign JWTs) |
| `enabled_nips` | array of integers | `[]` | Explicit NIP allowlist |
| `disabled_nips` | array of integers | `[]` | NIPs to disable (ignored when `enabled_nips` is non-empty) |
| `reject_ephemeral` | boolean | `false` | When `true`, NIP-01 ephemeral events (kinds 20000-29999) are rejected (`blocked: ephemeral events not allowed`) |
| `enabled_git` | boolean | `false` | When `true`, NIP-34 git events (kinds 1617-1633, 30617/30618) are accepted and NIP-34 is advertised. Default `false`: the kinds are rejected (`blocked: NIP-34 git events are disabled`) and NIP-34 is not advertised |
| `max_events_per_min_per_pubkey` | integer | `0` | Publish rate limit per pubkey (events per minute; `0` = no limit) |
| `require_auth` | boolean | `false` | Require NIP-42 authentication for all REQ/EVENT/COUNT/NEG |
| `send_auth_challenge` | boolean | `true` | Send the AUTH challenge on connect |
| `enabled_nip78_auth` | boolean | `true` | Require NIP-42 AUTH before accepting kind 78/30078 events and serve them only to the authenticated owner |
| `enabled_command_events` | boolean | `false` | Execute kind:1 operator commands authored by the admin pubkey `relay.pubkey` (see below) |

### Key details

**`name`** — The relay's display name. Served in the NIP-11 document and shown by clients in their relay list. May be changed at runtime via NIP-86 `changerelayname`, which persists the change into this config file.

**`description`** — A free-text description of the relay, shown alongside the name. Changed at runtime via `changerelaydescription` (persisted).

**`pubkey`** — Your administrator public key (64 hex chars). Served in the NIP-11 `pubkey` field so clients can message you (e.g. to report abuse). Purely informational.

**`contact`** — An alternative contact (URI such as `mailto:` or `https://`). Omitted from the NIP-11 document when empty.

**`icon`** — The relay's icon image URL, displayed in client relay lists. Omitted when empty.

**`post_policy`** — A URL where you describe your posting policy. Omitted when empty.

**`private_key`** — The relay's own secret key (64 hex chars). It signs **relay-generated events**: NIP-29 group metadata (39000-39005), NIP-43 role/membership events. Without it, NIP-29 groups still accept moderation events but produce **no 39001/39002 snapshots**, and NIP-43 is unavailable (a warning is logged). Generate with `nostrfy genkey`; keep it secret. Read once at startup — changing it requires a `restart`. The config file is created and kept at `0600` (`nostrfy init` creates it that way; `nostrfy genkey` enforces it after writing the key), so a loosely defaulted umask cannot leave secrets readable by other users.

**`public_url`** — The relay's public address, e.g. `wss://relay.example.com`. Used to validate URL-bearing tags from clients: NIP-42 AUTH (`relay` tag), NIP-62 vanish (`relay` tag), NIP-98 admin auth (`u` tag). When empty, the relay falls back to `host:port`, which never matches a real client URL when binding `0.0.0.0`/`127.0.0.1` (a warning is logged). **Always set this.**

**`livekit_url`** — The LiveKit server URL used for NIP-29 audio/video rooms. Together with the API credentials it enables `/.well-known/nip29/livekit`. Fixed at startup — requires a `restart`.

**`livekit_api_key`** — The LiveKit API key; appears as the `iss` claim of issued JWTs.

**`livekit_api_secret`** — The LiveKit API secret; the HMAC key for the JWT signature. An empty secret produces tokens LiveKit rejects (the relay warns about this combination).

**`enabled_nips`** — An explicit allowlist of NIP numbers. When non-empty, **only** these NIPs are advertised (NIP-11) and their relay-side behavior is active; `disabled_nips` is ignored. Requires a `restart` to change.

**`disabled_nips`** — Removes specific NIPs from the default set. For example `[50]` disables search (REQ/COUNT/API `search` is then ignored), `[28]` disables public-chat semantics. Requires a `restart` to change. Only relay-side NIPs are relevant: [1, 9, 11, 13, 17, 22, 26, 29, 32, 33, 34, 40, 42, 43, 45, 46, 47, 50, 57, 59, 62, 65, 66, 67, 70, 77, 78, 84, 85, 86, 87, 88, 94, 98] (NIP-28 is a behavior gate only — it is never advertised; NIP-A3 is a `draft` without an integer identifier, so it cannot appear in `supported_nips`; NIP-34 git events additionally require `relay.enabled_git`).

**`reject_ephemeral`** — When `true`, NIP-01 ephemeral events (kinds `20000-29999`) are rejected at publish time with `blocked: ephemeral events not allowed`. Exempt kinds that NIPs require to be relayed are still forwarded: `22242` (NIP-42 AUTH), `27235` (NIP-98 HTTP auth), `28934`/`28935`/`28936` (NIP-43 JOIN/Invite/LEAVE), `24133` (NIP-46 Nostr Connect), `23194`/`23195` (NIP-47 wallet request/response), `24242` (BUD-02 Blossom), `21059` (NIP-59 ephemeral gift wrap). Takes effect immediately on `SIGHUP` reload and on the next publish.

**`enabled_git`** — When `true`, NIP-34 git events (kinds `1617`-`1633`, `30617`/`30618`) are accepted and NIP-34 is advertised in the NIP-11 document. Default `false`: the kinds are rejected with `blocked: NIP-34 git events are disabled` (patch payloads can be large, so this is opt-in) and NIP-34 stays out of `supported_nips`. Takes effect immediately on `SIGHUP` reload and on the next publish.

**`require_pow`** — The required proof-of-work difficulty: the event id must start with at least this many zero bits (NIP-13), enforced only when NIP-13 is enabled. High values (≥ 64) make publishing practically impossible — the relay warns.

**`new_pubkey_min_age_secs`** — Spam defense: a pubkey's first accepted event is recorded, and events from pubkeys first seen less than this many seconds ago are rejected with `restricted: your account is too new`. `0` disables the check.

**`max_events_per_min_per_pubkey`** — A pubkey may publish at most this many events per minute (sliding 60-second window); the excess is rejected with `rate-limited: too many events`. The window is bounded at 10,000 tracked pubkeys (a full map is never cleared — tracked windows are preserved and fresh pubkeys alone are fail-open until old windows expire). `0` = unlimited.

**`max_groups`** — The cap on the in-memory NIP-29 group store. The store keeps the active groups plus a marker per deleted group (the marker is permanent so a deleted group cannot be resurrected), so without a cap an attacker could churn group ids and grow the memory without limit. The cap counts both, and group creation beyond it is rejected with `restricted: group limit reached` (both on the live write path and during the startup rebuild). `0` disables the cap. Read at startup — changing it requires a `restart`.

**`require_auth`** — When `true`, the relay refuses REQ/EVENT/COUNT/NEG messages with `auth-required:` unless the connection has completed NIP-42 AUTH. Useful for a private relay. Applied per connection.

**`send_auth_challenge`** — When `true`, every new connection receives a NIP-42 auth-request challenge. `require_auth = true` with `send_auth_challenge = false` locks everyone out — the relay warns about the combination at startup.

**`enabled_nip78_auth`** — NIP-78 application-specific events (kinds `78` and `30078`) are a private data store: when `true`, the relay requires the NIP-42 AUTH flow before accepting them (`auth-required: application-specific events require authentication`), and serves them only to the authenticated owner (the event author's pubkey) — REQ results, live events, COUNT and NIP-77 syncs withhold them from everyone else, and the unauthenticated REST API hides them. Set to `false` to restore the legacy behavior (public app-specific events). Requires NIP-42 to be enabled (the relay refuses to start otherwise) and is inactive when NIP-78 is disabled. Takes effect immediately on `SIGHUP` reload and on the next REQ/publish. Default `true`.

**`enabled_command_events`** — When `true`, kind:1 events authored by the admin pubkey (`relay.pubkey`) are executed as operator commands, so the allow/deny lists can be managed by publishing an event instead of running the CLI. The content must be exactly one of (the pubkey operand accepts `npub1...`, `nostr:npub1...` or 64-hex):
- `/relay allow <pubkey>` (alias: `/relay add`) — add a pubkey to the relay allow list
- `/relay deny <pubkey>` — add a pubkey to the relay deny list (removes it from allow)
- `/blossom allow <pubkey>` — add a pubkey to the Blossom upload allowlist
- `/blossom deny <pubkey>` — remove a pubkey from the Blossom upload allowlist

The changes take effect immediately and are persisted (same lists as `nostrfy relay allow/deny` and `nostrfy blossom allow/deny`). The relay answers every recognized command with a kind:1111 event signed with `relay.private_key`, tagged `e` to the command event and `p` to the admin pubkey (a mention, so clients show it as addressed to the admin); the reply is served publicly, so the result is visible even when NIP-42 is enabled. `error: ...` replies report unknown commands or invalid pubkeys. Only the admin (`relay.pubkey`) can issue commands — the author check runs on the event's verified signature. The admin and the relay's own pubkey are exempt from the pubkey allow/deny lists (publish and read), so commands keep working on `restrict_relay` relays. Requires both `relay.pubkey` (admin) and `relay.private_key` (reply signing); warnings are logged when the flag is on without them. Default `false`.

### Behavior notes

- **`name` / `description` / `icon` / `pubkey` / `contact`** are served to every client in the NIP-11 document (`GET /`). Empty string fields are omitted from the document. Runtime changes via NIP-86 are **persisted into this config file**, so a later SIGHUP reload keeps them.
- **`private_key`**: without it, no 39001/39002 group snapshots are generated. Generate with `nostrfy genkey`; changing requires `restart`.
- **`public_url`**: NIP-42/62 `relay`-tag matching tolerates different schemes (`wss`/`ws`/`https`/`http`) and paths, and is case-insensitive. NIP-98 `u`-tag matching is stricter: the tag must equal the relay's canonical HTTP URL exactly (the `public_url` authority with `wss` -> `https` / `ws` -> `http`, plus the exact path and query); each auth event is single-use within its 60-second window. When the relay binds `0.0.0.0` or `127.0.0.1` and `public_url` is empty, a loud warning explains that NIP-42/62/98 URL checks will fail.
- **`livekit_url` + `livekit_api_key` + `livekit_api_secret`**: all three are needed together; a URL without credentials logs a warning (tokens would be signed with an empty secret).
- **`enabled_nips` / `disabled_nips`**: `enabled_nips` wins over `disabled_nips`. Both affect the NIP-11 `supported_nips` list and the relay's behavior gates (NIP-29 groups, NIP-50 search, NIP-40 expiry, ...).
- **The NIP-11 `supported_nips` list is dynamic**: besides `enabled_nips`/`disabled_nips`, a NIP is dropped when every kind it defines is blocked — by `blocked_kinds`, by `allowed_kinds` (a NIP's kind is only accepted if it is listed), or by `reject_ephemeral` (a NIP whose kinds are all ephemeral and not in the exempt list is hidden). NIP-29/43/66 are hidden without `relay.private_key` (their relay-signed events cannot be produced), and NIP-86 is hidden without `rpc.management_token` or `rpc.admin_pubkey`. Kinds without an owning NIP are not affected. Runtime access changes (NIP-86 `allowkind`/`disallowkind`) and `SIGHUP` reloads are reflected in the next NIP-11 fetch; `enabled_nips`/`disabled_nips` still require a restart.

---

## 4. `[rpc]` — NIP-86 management RPC

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `management_token` | string | `""` | Bearer token for the management APIs |
| `admin_pubkey` | string (64 hex) | `""` | Administrator pubkey for NIP-98 management auth |
| `max_admin_body_bytes` | integer | `65536` | Body limit for the NIP-86 management RPC; oversized requests are refused with `413` |

### Key details

**`max_admin_body_bytes`** — The request body limit for the NIP-86 JSON-RPC handler mounted on the relay's public `POST /` routes (must be at least 1; `0` fails validation). NIP-86 requests are tiny method+params documents, so the 64 KiB default is generous while keeping the publicly reachable route from buffering large bodies. Management mutations are recorded in a rate-limited audit log (at most 600 entries per minute, then a single per-window summary line) with the authenticated identity.

## 5. `[server]` — server settings

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | `"127.0.0.1"` | Bind address. `0.0.0.0` (or `::`) accepts connections from anywhere |
| `port` | integer | `8080` | Port (1–65535). Port 80 requires root |
| `api_host` | string | `""` | Hostname dedicated to the REST API (must be a bare hostname — no scheme, port, path or whitespace; validated at `nostrfy check`/startup) |
| `metrics_enabled` | boolean | `true` | Serve Prometheus metrics at `/metrics` |
| `ws_paths` | string | `"root"` | WebSocket endpoint paths: `root` (`/` only), `inbox-outbox`, or `all` |
| `inbox_write_policy` | string | `"any"` | Write policy for `/inbox`: `any` or `relay` |
| `outbox_write_policy` | string | `"any"` | Write policy for `/outbox`: `any` or `relay` |

### Key details

**`host`** — The IP address the relay binds. `127.0.0.1` = local connections only (external clients get `connection refused`); `0.0.0.0` = all IPv4 interfaces; `::` = all IPv6 interfaces. Changing it changes who can reach the relay.

**`port`** — The TCP port, 1-65535; 80 requires root. This one port serves the WebSocket relay, the NIP-11 document, the REST API and the NIP-86 RPC together.

**`api_host`** — A hostname (e.g. `api.example.com`) dedicated to the REST API. Requests whose Host header matches it are served only `/api/v1`, `/health` and `/metrics`; every other host gets `404` for those paths, and the API host gets `404` for the relay endpoints. This lets you serve the API and the relay on the same port behind one reverse proxy. Host matching ignores case, `:port` suffixes and IPv6 brackets. Empty = the API is available on every host. Fixed at startup — requires a `restart`.

**`ws_paths`** — Which paths serve the WebSocket endpoint and the NIP-11 document: `root` serves `/` only (the default; the legacy `/ws` and `/ws/` paths are removed); `inbox-outbox` serves only `/inbox` and `/outbox`; `all` serves the root and the inbox/outbox paths. The inbox/outbox paths give the relay distinct endpoints for the inbox/outbox routing model (e.g. `wss://relay.example.com/inbox` and `wss://relay.example.com/outbox`). In `inbox-outbox` mode the root path returns 404 on every host except a configured Blossom host, where it answers the Blossom server-info document. Fixed at startup — requires a `restart`.

**`management_token`** — The bearer token that authenticates management calls (`Authorization: Bearer <token>`). Compared in constant time. Empty = token authentication is disabled.

**`admin_pubkey`** — The administrator's public key for NIP-98 authentication: management calls must carry a valid NIP-98 auth event (kind 27235, with a `payload` tag, a `u` tag matching the relay URL exactly, signed by this key). Empty = NIP-98 authentication is disabled. Each auth event is single-use within its 60-second window.

**`metrics_enabled`** — When `true`, serves Prometheus-formatted metrics at `/metrics` (no authentication). Fixed at startup — requires a `restart`.

### Behavior notes

- **`require_auth = true` with `send_auth_challenge = false`** locks everyone out — the challenge is never sent, so nobody can ever authenticate. The relay warns about this combination at startup.
- **`management_token` and `admin_pubkey`** can both be configured at once; either one authorizes. When both are empty, the management APIs are effectively disabled (every request gets `401`).
- The NIP-86 RPC is served on `POST /` of the main port (and on the paths selected by `server.ws_paths`).

---

## 6. `[limits]` — limits and protections

### Connections and messages

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_connections` | integer | `10000` | Maximum concurrent connections (must be ≥ 1) |
| `max_connections_per_ip` | integer | `64` | Max connections per source IP (`0` = no per-IP cap) |
| `max_ws_message_bytes` | integer | `1048576` | Max bytes per WebSocket message/frame |
| `buffer_size` | integer | `2048` | Initial per-connection WebSocket buffer (bytes; legacy location of `database.db_buffer_size`) |
| `socket_recv_buffer_kb` | integer | `64` | Per-connection kernel receive buffer (KiB, `0` = kernel default; the kernel may double it). Larger values let a fast publisher's burst absorb into one batch while the relay commits; the buffer uses real memory only while data is queued |
| `max_out_queue_bytes` | integer | `262144` | Per-connection outgoing queue cap (bytes; `0` = unlimited) |
| `ws_idle_timeout_secs` | integer | `300` | Close idle connections after this long (`0` = never) |
| `http_read_timeout_secs` | integer | `30` | Seconds to deliver a complete HTTP request head before the connection is closed (`0` = disabled; slow-loris defense — applies to WebSocket upgrades too) |
| `max_connections_per_sec_per_ip` | integer | `0` | Max new connections per second per source IP (`0` = unlimited) |
| `max_events_per_min_per_pubkey` | integer | `0` | Max events a pubkey may publish per minute (`0` = unlimited) |
| `max_req_response_bytes` | integer | `33554432` | Byte budget for one REQ response (`0` = unlimited); beyond it the subscription is closed with `CLOSED` |

### Subscriptions and queries

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_filters` | integer | `20` | Max filters per REQ |
| `max_subscriptions` | integer | `20` | Max subscriptions per connection (REQ and NEG) |
| `max_limit` | integer | `500` | Ceiling for the REQ `limit` |
| `max_count` | integer | `2000` | Ceiling for COUNT results |
| `max_sub_id_len` | integer | `64` | Max subscription id length |
| `max_sub_bytes` | integer | `1048576` | Total subscription filter bytes per connection |

### Events

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_content_bytes` | integer | `65536` | Max event content length in **characters** |
| `max_groups` | integer | `1000` | Cap on the in-memory NIP-29 group store (active groups + deleted-group markers). Creates beyond it are rejected with `restricted: group limit reached`. `0` = unlimited |
| `max_tags` | integer | `2000` | Max tags per event |
| `max_tag_value_bytes` | integer | `1024` | Max bytes per tag value |
| `max_created_at_future_secs` | integer | `3600` | Tolerated future skew of `created_at` (seconds) |
| `require_pow` | integer | `0` | Required proof-of-work difficulty in leading zero bits |
| `max_indexed_words` | integer | `32` | Words of content indexed for NIP-50 search |

### Database queue and overload protection

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `db_queue_msgs` | integer | `4096` | Max queued messages before failing fast (legacy location of `database.max_db_queue_msgs`) |
| `db_queue_events` | integer | `262144` | Max queued events before failing fast (legacy location of `database.max_db_queue_events`) |
| `max_neg_items` | integer | `100000` | Max records per NIP-77 negentropy sync |
| `live_buffer` | integer | `65536` | Live fan-out queue size |

### Anti-spam

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `new_pubkey_min_age_secs` | integer | `0` | Reject events from pubkeys younger than this (seconds) |
| `group_late_publish_secs` | integer | `3600` | NIP-29: reject group events older than this (seconds) |

### REST API

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_api_concurrent` | integer | `8` | Max concurrent `/api/v1` requests (503 beyond this) |
| `max_api_queue_msgs` | integer | `512` | Max queued `/api/v1` requests for the API reader (fail-fast beyond this) |
| `max_api_limit` | integer | `5000` | Ceiling for the API `limit` parameter (`0` = no bound) |
| `max_api_offset` | integer | `50000` | Ceiling for the API `offset` parameter (`0` = no bound) |
| `max_api_search_bytes` | integer | `2048` | Max bytes of the API `search` parameter (`0` = no bound) |

### Live fan-out

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `live_batch_interval_ms` | integer | `20` | How often live events are flushed (ms) |
| `live_batch_size` | integer | `32` | Max events per live batch |

### Key details

**`max_connections`** — The total number of concurrent connections (WebSocket and HTTP). New connections beyond this are refused at the socket level. Must be ≥ 1.

**`max_connections_per_ip`** — The number of simultaneous connections allowed from a single source IP. Prevents one host from consuming the whole connection budget. `0` = unlimited.

**`max_ws_message_bytes`** — The maximum size of a single WebSocket message/frame in bytes. Oversized frames are rejected at the protocol layer and the connection is closed with a `message too large` notice. Also the effective ceiling for any single event.

**`max_out_queue_bytes`** — The per-connection cap on queued outgoing bytes, protecting memory against slow readers (`0` = unlimited). REQ responses are pumped through the queue in bounded chunks (see `max_req_response_bytes`), so they cannot pin more than the cap either; EOSE and CLOSED messages are tiny and take the uncapped path. Live traffic is dropped when full (recoverable by re-subscribing).

**`max_req_response_bytes`** — Byte budget for a single REQ response (the stored events delivered for one subscription). The response is pumped into the capped outgoing queue in chunks as the socket drains; when the budget is exceeded the subscription is closed with `CLOSED ... blocked: response too large; narrow the filter or paginate` and the client can re-request with a narrower filter. `0` disables the budget. A connection may queue at most four pending responses; older ones are cut off with their EOSE.

**`ws_idle_timeout_secs`** — Connections with no inbound frames for this long are closed. While enabled, the relay also sends periodic WebSocket PINGs: healthy clients answer with a PONG (an inbound frame, which resets the timer) and stay connected; dead peers are reaped. `0` = disabled (no timeout, no pings).

**`http_read_timeout_secs`** — Seconds a connection has to deliver a complete HTTP request head (the request line and headers) before it is closed. This closes slow-loris sockets that trickle bytes without ever completing a request — the attack would otherwise pin file descriptors and memory. Applies to every HTTP connection, WebSocket upgrades included (an upgrade request is a normal HTTP request head). `0` disables the timeout.

**`max_connections_per_sec_per_ip`** — Maximum number of new connections a single source IP may open per second (sliding window). Sockets beyond the window are refused immediately. `0` = unlimited.

**`max_filters`** — The maximum number of filters a single REQ (or COUNT) may carry. Violations get a `CLOSED ... too many filters` reply. This also bounds scanning work per REQ.

**`max_subscriptions`** — The maximum number of simultaneous subscriptions (REQ and NEG) per connection. Violations get `error: too many subscriptions`.

**`max_limit`** — The ceiling for the `limit` value in filters. Clients asking for more get at most this many events per filter, with the NIP-67 `["EOSE", sub, ["more"]]` hint when more events exist.

**`max_count`** — The ceiling for COUNT results. When the count is cut at this value, the response carries `"approximate": true`.

**`max_sub_id_len`** — The maximum length of a subscription id. Longer ids are refused.

**`max_sub_bytes`** — The total bytes of all subscription filters held by one connection. Prevents a connection from pinning many megabytes of filter data.

**`max_content_bytes`** — The maximum length of an event's `content` field, counted in **characters** (not bytes), matching the NIP-11 `max_content_length` definition. Events above it are rejected with `invalid: content too large`.

**`max_tags`** — The maximum number of tags per event. Violations are rejected with `invalid: too many tags`.

**`max_tag_value_bytes`** — The maximum size (bytes) of a single tag value. Longer values are rejected with `invalid: tag value too large`.

**`max_created_at_future_secs`** — How far into the future an event's `created_at` may be. Beyond this the event is rejected as invalid (`OK false` with `invalid: event creation date is in the future`).

**`max_neg_items`** — The maximum number of records a single NIP-77 negentropy sync may process. Larger syncs are refused with a `NEG-ERR`.

**`live_buffer`** — The size of the fan-out queue between the relay and the broadcaster. On overflow, events are dropped for live delivery (they stay available via subscriptions).

**`new_pubkey_min_age_secs`** — Spam defense: the relay records when a pubkey's first event was accepted, and events from pubkeys younger than this window are rejected with `restricted: your account is too new`. A rejected first event does **not** start the clock. `0` = disabled.

**`group_late_publish_secs`** — NIP-29: group events older than this many seconds are rejected (`invalid: event is too old for this group`), preventing re-writing of group history. `0` = disabled.

**`max_api_concurrent`** — The maximum number of `/api/v1` requests served at once. Beyond it, new requests get `503 server is busy` immediately instead of queueing.

**`max_api_queue_msgs`** — The maximum number of queued-but-unprocessed `/api/v1` requests waiting for the dedicated API reader thread. Beyond it, requests fail fast with an empty result instead of piling up in memory. Independent from the WebSocket-side queue caps; applied live on SIGHUP reload.

**`max_api_limit`** — The ceiling for the API's `limit` parameter. Requests above it are silently clamped down. `0` = no bound.

**`max_api_offset`** — The ceiling for the API's `offset` parameter. Requests above it are rejected with a `400` explaining the limit. `0` = no bound.

**`max_api_search_bytes`** — The maximum length (bytes) of the API's `search` parameter. Longer values are rejected with a `400`. `0` = no bound.

**`live_batch_interval_ms`** — How often (milliseconds) accumulated live events are flushed to subscribers (clamped to 1-1000).

**`live_batch_size`** — The maximum number of events per flushed live batch (must be ≥ 1).

### Behavior notes

- **`max_created_at_future_secs`** uses the NIP-01 `invalid:` prefix — the event is rejected as invalid (the NIP-01 example for this case).
- **`max_out_queue_bytes`** protects against slow readers; REQ responses are never dropped by it (see key details).
- **`new_pubkey_min_age_secs`**: the first-seen timestamp is only recorded when an event actually stores, so failed first events cannot pre-warm the account-age clock.
- **`max_api_limit`** clamps silently; **`max_api_offset`** and **`max_api_search_bytes`** reject with a clear `400` error message.
- COUNT with hidden events (NIP-70/59/29) reports the *visible* count, preserving privacy.

---

## 7. `[database]` — database settings

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | string | `"./data"` | Database directory (LMDB) |
| `max_dbs` | integer | `32` | LMDB max named databases (must be ≥ 17) |
| `max_readers` | integer | `128` | LMDB max concurrent readers (must be ≥ 8) |
| `map_size` | integer | `1073741824` (1 GB) | Floor for the memory map size (bytes) |
| `max_map_size` | integer | `1099511627776` (1 TB) | Memory-map ceiling (bytes) |
| `purge_interval_secs` | integer | `300` | NIP-40 purge interval (seconds) |
| `search_index` | boolean | `true` | Enable the NIP-50 word index |
| `reader_threads` | integer | `2` | Dedicated scan threads (1-64) |
| `max_indexed_words` | integer | `32` | Words of each event's content indexed for search |
| `meta_index` | boolean | `true` | Write the per-event metadata header used by the scan prefilter. Disabling it drops one random index write per event (ingest stays flat as the database grows) at the cost of scans falling back to the full parse |
| `disabled_fsync` | boolean | `false` | Skip the synchronous disk flush after every write batch (`MDB_NOSYNC`). Multiplies ingest throughput at the cost of durability: a power loss may lose the most recent writes |

### Key details

**`path`** — The directory holding the LMDB database files. Relative paths are resolved against the config file's directory, so they stay valid after the daemon changes its working directory. Do not point two relay instances at the same directory.

**`max_dbs`** — LMDB's maximum number of named databases. The relay uses 17 when `search_index = true` (16 tables plus the word index) and 16 otherwise; values below 17 are raised to 17 so the word index can always be created.

**`max_readers`** — LMDB's maximum number of concurrent read transactions. Must be ≥ 8; the relay uses three threads (writer, reader, API reader).

**`map_size`** — The floor for the memory map size in bytes. The map is opened at least this large (1 GB default).

**`max_map_size`** — The memory-map ceiling in bytes. The map is opened at this size as a **sparse virtual reservation** — physical disk grows only with the data actually written, so a large ceiling costs nothing until used. When the map fills, writes fail with `database map is full: increase database.max_map_size` (reads keep working). Must be ≥ `map_size`.

**`purge_interval_secs`** — How often (seconds) NIP-40 expired events are physically removed from the database. Expired events are hidden from queries even between purges.

**`search_index`** — When `true`, event content is word-indexed for fast NIP-50 search. When `false`, search still works (whole-word matching against content) but scans are slower. Toggling takes effect at startup. For a tiny VPS (0.25 vCPU / 512 MB) set `search_index = false` — it **halves the database** (41.8 MB → 20.5 MB per 10,000 events with 3 tags and 21 words in testing) and saves CPU/IO; see the Manual's [Low-spec Tuning](MANUAL.md#low-spec-vps-025-vcpu--512-mb).
**`db_buffer_size`** — The initial per-connection WebSocket buffer in bytes (grows on demand); the kernel receive buffer is tuned separately with `limits.socket_recv_buffer_kb`.
**`max_indexed_words`** — How many words of each event's content are added to the NIP-50 search index. Higher values improve index-based recall for long texts at a small storage cost; words past the cap are still matched — long events carry an overflow marker and the search scan checks their full content — so lowering this trades query speed for index size, not correctness.
**`db_request_timeout_secs`** — How long a database request may wait before it fails (`0` = forever). Keeps the relay responsive when the storage is stuck. Write requests are not subject to the timeout (a false timeout would skip their side effects). The startup loads of the persisted access state (deny/allow lists, Blossom allowlist) wait without a timeout and never fail fast: an empty result would silently lift every ban (fail-open). Their SIGHUP reloads keep the previous lists when a load fails.
**`disabled_fsync`** — Skip the synchronous disk flush after every write batch (LMDB `MDB_NOSYNC`). Writes are committed to the mapped pages and left in the OS page cache, so commits cost microseconds instead of an fsync; the kernel flushes them shortly after. A power loss or OS crash may lose the writes since the last kernel flush — a fine trade for a high-throughput relay with a replica/backup, a poor one for a single always-live instance. Takes effect at startup. The Manual's [Throughput tuning](MANUAL.md#throughput-events-per-second) section shows the settings that move ingest throughput.
**`max_db_queue_msgs`** — When the database queue holds more than this many pending messages, new requests fail fast instead of piling up in memory.
**`max_db_queue_events`** — Like `max_db_queue_msgs`, but counts the events inside queued batches (the memory-dominant part). Whichever limit is hit first applies.


### Behavior notes

- The memory map is never resized at runtime: raising `max_map_size` requires a `restart`.
- `map_size` must not exceed `max_map_size` (`nostrfy check` rejects the combination).
- Search semantics are the same with or without the index: whole-word matching (see the troubleshooting guide).

### Upgrades are automatic and instant

- **Tables**: every LMDB table is opened-or-created at startup (`create_database`) — a database written by an older version simply gets its missing tables added instantly, with the existing data untouched (verified by the schema-upgrade test: an ancient DB with only the `events` table boots with events, access control and the Blossom mapping all working).
- **Columns** (keys within a table): keyed entries are dynamic — no migration needed.
- **Data migrations** run automatically once, at startup:
  - access pubkey lists moved into their dedicated key (legacy `access` blob → `relay_pubkeys`),
  - the Blossom sha→owner mapping rebuilt from legacy files (marker key, skipped on later restarts).
- The startup log reports `database ready at ... (14 tables, map ... MiB)` and the migration checks.

---

## 8. `[daemon]` — daemon settings

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `pid_file` | string | `"./nostrfy.pid"` | PID file path |
| `log_file` | string | `"./nostrfy.log"` | Log file path |
| `stats_file` | string | `"./nostrfy.stats.json"` | Statistics file path |
| `stats_interval_secs` | integer | `5` | Statistics write interval (seconds) |
| `max_log_size_bytes` | integer | `52428800` (50 MB) | Log rotation size (`0` = no rotation) |
| `max_log_files` | integer | `5` | Rotated log generations to keep |

### Key details

**`pid_file`** — Where the daemon writes its process id. `stop`/`restart` use it to signal the daemon. A stale entry (dead process, or a pid reused by a different program) is detected and ignored.

**`log_file`** — Where the daemon writes its log. Rotated when it grows past `max_log_size_bytes`.

**`stats_file`** — Where live statistics are written (atomically, via temp-file + rename) every `stats_interval_secs` seconds. Read by `nostrfy stats`; the same data is served at `/relay/stats`.

**`stats_interval_secs`** — How often the statistics file is refreshed (≥ 1).

**`max_log_size_bytes`** — Rotate the log when it reaches this size (`0` = never rotate). The current file becomes `.1`, older backups shift up.

**`max_log_files`** — How many rotated generations to keep (`.1`, `.2`, ... `.N`); older backups are discarded.

### Behavior notes

- Paths may be relative; they are resolved against the config file's directory so they survive the daemon's working-directory change.
- Log rotation happens per write: the log never grows far past the configured size.

---

## 9. `[access]` — access control

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `restrict_relay` | boolean | `false` | When true, only the pubkeys on the allow list may publish |
| `blocked_kinds` | array of integers | `[]` | Kinds to reject |
| `allowed_kinds` | array of integers | `[]` | Kind allowlist — when non-empty, only these kinds are accepted |
| `blocked_ips` | array of strings | `[]` | IP addresses refused at connection time |

### Key details

**`restrict_relay`** — The pubkey **allow/deny lists are not config state**: they live in the relay database (LMDB) and are managed at runtime with:

```sh
nostrfy relay allow npub1...      # allow a pubkey to publish (npub1... or hex)
nostrfy relay deny npub1...       # deny a pubkey — its events are always rejected
nostrfy relay list                # show both lists and restrict_relay
```

- `restrict_relay = true`: **only** the pubkeys on the allow list may publish (everyone else is rejected with `blocked: pubkey not allowed`). This is the NIP-11 `restricted_writes` semantics: **reading stays open to everyone** (anonymous and non-listed pubkeys can still subscribe), so an allowed pubkey's posts remain publicly readable. Denied pubkeys are the only ones refused reads.
- `restrict_relay = false` (default): everyone may publish **except** the denied pubkeys — a denied entry always wins, with or without `restrict_relay`.
- **The restriction is write-only**: reading is never limited — any client may query/subscribe, fetch via the REST API and browse the NIP-11 document, regardless of the allow/deny lists.
- Each `allow`/`deny` writes the database and reloads the running daemon (SIGHUP), so the change applies immediately. NIP-86 (`banpubkey`/`allowpubkey`/...) manages the same lists.
- Databases from older versions are migrated once at startup: pubkey entries that used to live in the config/`access` blob are copied into the dedicated database key.

**`blocked_kinds`** — Event kinds that are rejected (`blocked: kind not allowed`).

**`allowed_kinds`** — The kind allowlist. When non-empty, only the listed kinds are accepted.

**`blocked_ips`** — IP addresses whose connections are refused at the WebSocket layer (and the NIP-86 RPC). `blockip` also drops the IP's existing connections.

### Behavior notes

- The kinds/IP lists are seeded at startup and then **managed at runtime** through NIP-86. Runtime changes are persisted in the database and survive restarts; once runtime state exists, it takes precedence over the config section.
- The reason is reported by the NIP-86 list methods (`listbannedpubkeys`, `listblockedips`, ...).
- `blocked_ips` entries must parse as IP addresses (`nostrfy check` validates them).

---

## 8b. `[blossom]` — Blossom file server (media hosting)

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | `""` | Hostname dedicated to the Blossom server, e.g. `media.example.com` (must be a bare hostname — no scheme, port, path or whitespace; validated at `nostrfy check`/startup). Empty = the feature is disabled |
| `storage` | string | `"local"` | Storage backend: `"local"` or `"s3"` (any S3-compatible service, including Cloudflare R2) |
| `local_path` | string | `"./data/images"` | Local storage directory: `<local_path>/<npub1...>/<sha256>` |
| `max_upload_bytes` | integer | `20971520` | Maximum accepted upload size (the `PUT /upload` body limit) |
| `min_free_bytes` | integer | `33554432` | Local-storage disk-full guard: uploads are refused with `507` while the free space on the filesystem hosting `local_path` is below this many bytes (a full disk would otherwise risk SIGBUS on the LMDB memory map). `0` disables the check |
| `s3_endpoint` | string | `""` | S3 endpoint, e.g. `https://<account>.r2.cloudflarestorage.com` for R2 |
| `s3_region` | string | `""` | S3 region (R2 uses `"auto"`) |
| `s3_bucket` | string | `""` | S3 bucket — the `bucket` of the `bucket/{npub1}/{file}` layout |
| `s3_access_key` | string | `""` | S3 / R2 access key |
| `s3_secret_key` | string | `""` | S3 / R2 secret key |
| `restrict_uploads` | boolean | `false` | When true, only the pubkeys in the Blossom upload allowlist may upload blobs |


### Key details

**`host`** — Works like `server.api_host`: requests whose Host header names this hostname are served only the Blossom routes on the same port, so a single reverse proxy can split `relay.example.com` (relay) from `media.example.com` (files). The root path `/` answers with the Blossom server info document on this host.

**`storage`** — `"local"` keeps files on the server disk; `"s3"` stores objects in an S3-compatible bucket (AWS S3 or Cloudflare R2). Both use the `bucket/{npub1xxx}/{file}` hierarchy: files are content-addressed by their SHA-256 and kept under the uploader's npub directory.

**`max_upload_bytes`** — The HTTP body limit for uploads. Note that `limits.max_ws_message_bytes` is unrelated (it governs WebSocket events).

**`local_path`** — Local storage. The store refuses paths that a local attacker has replaced with symlinks (reads, writes and deletes never follow a symlinked blob file or npub directory), so the blob tree cannot be redirected outside the configured root.

**`min_free_bytes`** — Local-storage disk-full guard. Before writing a blob, the relay checks the free space on the filesystem hosting `local_path` (the same `statvfs` check the LMDB writer uses) and refuses the upload with `507 Insufficient Storage` while the free space is below this margin — a full disk would otherwise fail the LMDB writer and risk SIGBUS on memory-map writes. `0` disables the check. The S3 backend has no local disk, so the guard only applies to `storage = "local"`.

**S3 keys** — With `storage = "s3"`, `s3_endpoint`, `s3_bucket`, `s3_access_key` and `s3_secret_key` are required. The endpoint must be the *path-style* HTTPS form (`https://s3.amazonaws.com` or `https://<account>.r2.cloudflarestorage.com`); the request signing follows AWS Signature Version 4. Plain `http://` is rejected because SigV4 credentials would travel in cleartext — only loopback hosts (`127.0.0.1`, `localhost`, `[::1]`) may use `http://`, so a local MinIO remains usable for testing.

**`restrict_uploads`** — When `true`, `PUT /upload` accepts only the pubkeys on the Blossom upload allowlist (everyone else gets `403`). The allowlist itself is **not** part of the config file: it lives in the relay database (LMDB), is loaded at startup and managed at runtime with:

```sh
nostrfy blossom allow npub1...     # add a pubkey (npub1... or hex)
nostrfy blossom deny npub1...     # remove a pubkey
nostrfy blossom list             # show the list and the restrict flag
```

Each `allow`/`deny` writes the database and reloads the running daemon (SIGHUP), so the change applies immediately.

### Behavior notes

- The feature is completely off when `host` is empty — no routes, no storage directories.
- Blob bytes never enter the LMDB database: uploads, fetches and deletes operate on the configured local filesystem or S3 bucket. LMDB does persist the SHA-256-to-owner metadata and upload allowlist, so both the blob storage and relay database are required for a complete backup.
- Storage I/O is asynchronous (`tokio::fs` / the `reqwest` client) — relay and WebSocket performance is unaffected.
- The sha256 → owner mapping is persisted in the relay database (LMDB): no in-memory index and no startup scan, so lookups survive restarts and memory stays bounded. Uploads write the mapping first (a crash leaves a healable state); deleting a blob removes its mapping.
- **Automatic one-time migration**: at startup the relay checks whether the `blossom` mapping table exists (created instantly if missing) and whether the legacy migration already ran (marker key). If not, it scans the storage in the background (local directories / bucket objects, with or without the legacy `.meta.json` files) and rebuilds the mapping — the relay starts immediately and existing blobs become reachable as the migration completes. Later restarts skip it. Legacy multi-owner blobs keep every uploader's mapping, and the writes are chunked so a large migration never blocks the relay's event writes for long. If a migration batch fails (e.g. the LMDB map is full), the marker is left unset and the migration retries on the next start. **Backup restore**: if you restore an old storage directory/bucket without its database, delete the database directory first (or upload the blobs again) — the migration marker then triggers a fresh scan.
- Only the uploader (the pubkey whose npub directory holds the file) can delete a blob.
- Uploads and deletes are authorized with Blossom auth events (kind 24242, `t` + `server` tags, a mandatory `expiration` tag in the future, and an `x` tag with the blob hash for upload/delete/media per BUD-11). An optional `X-SHA-256` header is verified against the request body (mismatch = 409). `PUT /media` / `HEAD /media` (BUD-05) and `HEAD /upload` (BUD-06) are supported with the same policy; the CORS pre-flight allows the `X-SHA-256` / `X-Content-Type` / `X-Content-Length` headers. Local files are written atomically (temp file + rename), so a crash cannot leave a truncated blob.
- The upload allowlist is persisted in the relay database under a fixed key of the existing `access` table — no new LMDB table is created, so databases from older versions stay compatible.

---

## 10. Validation rules

`nostrfy check` (and startup) rejects invalid configurations with a clear message:

| Rule | Error example |
| --- | --- |
| `pubkey`/`admin_pubkey`/access pubkeys must be 64 hex chars | `relay.pubkey must be 64 hex characters (32 bytes)` |
| `private_key` must be a valid secp256k1 secret key | `relay.private_key is not a valid secp256k1 secret key` |
| `port` must be 1–65535 | `server.port must be between 1 and 65535` |
| `api_host` / `blossom.host` must be bare hostnames | `server.api_host must be a bare hostname (no scheme, port or path), got "https://..."` |
| `api_host` must differ from `blossom.host` | `server.api_host and blossom.host must be different hostnames` |
| blocked IPs must parse | `access.blocked_ips contains an invalid IP address: "..."` |
| `map_size` ≤ `max_map_size` | `database.map_size must not exceed database.max_map_size` |
| Core limits must be ≥ 1 | `limits.max_connections must be at least 1 (got 0)` |
| Paths must not be empty | `database.path must not be empty` |

Unknown keys or sections produce **warnings** (not errors), so typos are visible:

```
[WARN] unknown config key [server].potr is ignored; check the spelling ...
[WARN] unknown config section [serve] is ignored; check the spelling ...
```

---

## 10. Reloading at runtime (SIGHUP)

Editing the file and sending `kill -HUP $(cat nostrfy.pid)` reloads it **without a restart**. Most settings take effect immediately; a few are fixed at startup:

| Applies on SIGHUP | Requires `nostrfy restart` |
| --- | --- |
| `relay.name`, `description`, `pubkey`, `contact`, `icon`, `post_policy`, `public_url`, `relay.reject_ephemeral`, `relay.enabled_git`, `relay.enabled_nip78_auth` | `relay.private_key` |
| most of `[limits]` (the restart-column entries below apply on restart only) | `relay.livekit_*`, `relay.enabled_nips` / `disabled_nips` |
| — | `database.path`, `database.purge_interval_secs`, `database.map_size`, `database.max_map_size`, `database.search_index`, `database.meta_index`, `database.reader_threads`, `database.disabled_fsync`, `database.db_request_timeout_secs`, `database.max_db_queue_msgs`, `database.max_db_queue_events`, `database.max_indexed_words`, `daemon.max_log_size_bytes`, `max_log_files`, `stats_interval_secs`, `limits.live_buffer`, `live_batch_size`, `live_batch_interval_ms`, `socket_recv_buffer_kb`, `max_connections`, `http_read_timeout_secs`, `max_connections_per_sec_per_ip`, `rpc.max_admin_body_bytes`, `relay.max_groups`, `blossom.host`, `blossom.storage`, `blossom.local_path`, `blossom.max_upload_bytes`, `blossom.min_free_bytes`, `blossom.s3_*` |

`[access]` is **not** applied by a reload: the access lists are seeded once at startup and then managed at runtime via NIP-86.

The log warns when one of the restart-required settings changed (`... a restart is required to apply it`). A few startup-captured settings (`relay.max_groups`, the LMDB map size floor) are not checked by the reload.

---

## 11. Full example

```toml
[relay]
name = "My Relay"
description = "A friendly relay for everyone"
pubkey = ""
contact = "mailto:admin@example.com"
icon = "https://example.com/icon.png"
post_policy = ""
private_key = ""
public_url = "wss://relay.example.com"
livekit_url = ""
livekit_api_key = ""
livekit_api_secret = ""
enabled_nips = []
disabled_nips = []
reject_ephemeral = false
enabled_git = false

[server]
host = "0.0.0.0"
port = 8080
api_host = "api.example.com"
management_token = ""
admin_pubkey = ""
require_auth = false
send_auth_challenge = true
enabled_nip78_auth = true
metrics_enabled = true

[limits]
max_connections = 10000
max_connections_per_ip = 64
max_ws_message_bytes = 1048576
max_filters = 20
max_subscriptions = 20
max_limit = 500
max_count = 2000
max_sub_id_len = 64
max_content_bytes = 65536
max_tags = 2000
max_tag_value_bytes = 1024
max_created_at_future_secs = 3600
require_pow = 0
max_indexed_words = 32
db_buffer_size = 2048
max_neg_items = 100000
db_request_timeout_secs = 30
new_pubkey_min_age_secs = 0
max_out_queue_bytes = 262144
ws_idle_timeout_secs = 300
max_db_queue_msgs = 4096
max_db_queue_events = 262144
max_sub_bytes = 524288
group_late_publish_secs = 604800
max_api_concurrent = 32
max_api_limit = 500
max_api_offset = 10000
max_api_search_bytes = 1024
http_read_timeout_secs = 30
max_connections_per_sec_per_ip = 0
max_events_per_min_per_pubkey = 0
max_req_response_bytes = 33554432
live_batch_interval_ms = 10
live_batch_size = 64
live_buffer = 65536

[database]
path = "./data"
max_dbs = 32
max_readers = 128
map_size = 1073741824
max_map_size = 1099511627776
purge_interval_secs = 300
search_index = true
disabled_fsync = false

[daemon]
pid_file = "./nostrfy.pid"
log_file = "./nostrfy.log"
stats_file = "./nostrfy.stats.json"
stats_interval_secs = 5
max_log_size_bytes = 52428800
max_log_files = 5

[access]
restrict_relay = false
blocked_kinds = []
allowed_kinds = []
blocked_ips = []
```

---

## 12. Common mistakes

| Mistake | Symptom | Fix |
| --- | --- | --- |
| `public_url` unset | NIP-42 auth fails, warning at startup | Set `public_url = "wss://..."` |
| `host = "127.0.0.1"` left as-is | External clients cannot connect | `host = "0.0.0.0"` |
| `private_key` unset with NIP-29 enabled | No group metadata (39000-39005) | `nostrfy genkey` + `restart` |
| String without quotes | TOML parse error | `name = "my relay"` |
| `restrict_relay = true` with an empty allow list | Everyone is locked out | `nostrfy relay allow <npub>` the intended pubkeys |
| Changing `private_key`/`api_host` and only SIGHUPing | Change does not apply | Use `nostrfy restart` |
| Values written as floats (`1.5`) or strings (`"8080"`) | Config/parse errors | Use plain integers |

---

## Related

- [Manual (MANUAL.md)](MANUAL.md)
- [Troubleshooting (TROUBLESHOOTING.md)](TROUBLESHOOTING.md)