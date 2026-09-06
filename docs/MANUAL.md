# nostrfy Manual

This manual explains every feature of **nostrfy**, a Nostr relay server, step by step — from installation to everyday operation.

## Table of Contents

1. [What is nostrfy](#1-what-is-nostrfy)
2. [Installation](#2-installation)
3. [The Config File (nostrfy.toml)](#3-the-config-file-nostrfytoml)
4. [Starting and Stopping](#4-starting-and-stopping)
5. [Command Reference](#5-command-reference)
6. [REST API](#6-rest-api)
7. [NIP-86 Management API](#7-nip-86-management-api)
8. [Supported NIPs](#8-supported-nips)
9. [NIP-29 Groups](#9-nip-29-groups)
10. [LiveKit (Audio/Video Rooms)](#10-livekit-audiovideo-rooms)
11. [Blossom File Server (Media Hosting)](#11-blossom-file-server-media-hosting)
11b. [Running Multiple Instances](#11b-running-multiple-instances)
12. [Logs and Statistics](#12-logs-and-statistics)
13. [Reloading Configuration (SIGHUP)](#13-reloading-configuration-sighup)
14. [Large-Scale Deployments](#14-large-scale-deployments)
15. [When You Are Stuck](#15-when-you-are-stuck)

---

## 1. What is nostrfy

nostrfy is a **relay server** for the [Nostr](https://nostr.com/) protocol. It stores events (posts, reactions, profiles, ...) sent by clients (nos2x, Amethyst, Damus, Iris, and others) and delivers them in response to subscription requests.

Key features:

- **Simple and stable**: written in Rust; a single binary does everything
- **Fast storage and search**: LMDB database with a full-text search index
- **Broad NIP support**: 36 NIPs implemented (plus the Blossom file server), including deletion, proof-of-work, delegation, groups, search, and a management API
- **Easy to operate**: daemon mode, log rotation, hot configuration reload, statistics output, a REST API, and Prometheus metrics

---

## 2. Installation

### Requirements

- A recent stable Rust toolchain
- A Linux machine (2 GB of RAM or more is recommended — see [Low-spec Tuning](#low-spec-vps-025-vcpu--512-mb) for 0.25 vCPU / 512 MB)

### Low-spec VPS (0.25 vCPU / 512 MB)

nostrfy is verified to run stably even when the database exceeds RAM. The LMDB map is a **sparse 1 TiB virtual reservation** — physical disk grows only with the data written — and the process memory stays flat: a relay with a 252 MB database held **7.9 MB of private RSS** (the rest is reclaimable file cache the kernel evicts under pressure).

For a tiny VPS, one setting makes the biggest difference:

```toml
[database]
search_index = false   # halves the database size and saves CPU/IO
```

| Setting | Effect | Measured |
| --- | --- | --- |
| `search_index = false` | Disables the NIP-50 word index — search still works (whole-word matching by scanning content) but is slower. Recommended when full-text search is not needed | 41.8 MB → **20.5 MB** per 10,000 events (each with 3 tags and 21 words) |
| Defaults | Already tiny: `db_buffer_size = 2048`, bounded queues, no per-connection growth | No change needed for 512 MB |

If you need search on a tiny VPS, keep `search_index = true` and lower `max_indexed_words` (e.g. 32) instead — it caps the per-event word cost. All other defaults are already tuned for low memory: the per-connection buffers are small, the LMDB map never needs resizing at runtime, and the relay restarts instantly (no in-memory index to rebuild).

### Building

```bash
git clone https://github.com/iqbqioza/nostrfy.git
cd nostrfy
cargo build --release
```

When the build finishes, the binary is at `target/release/nostrfy`.

### Installing a pre-built binary

The release workflow attaches pre-built binaries for **Linux x86_64**,
**Linux aarch64** and **FreeBSD x86_64**. The same `install.sh` works on
both OSes — it detects the platform, downloads the matching binary and
verifies its checksum:

```sh
curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrfy/main/install.sh | sh
```

#### FreeBSD

nostrfy builds and runs on FreeBSD (13.x and 14.x, amd64). Install Rust
and build with:

```sh
pkg install -y rust   # clang ships with the FreeBSD base system
cargo build --release
```

Platform notes:

- The process-alive check used by `start`/`stop`/`restart` reads the
  process name via the `kern.proc.pid.<pid>.comm` sysctl on FreeBSD (it
  uses `/proc/<pid>/comm` on Linux), so a stale pid file whose pid was
  reused by another program is detected on both platforms.
- `daemon.mode` forks like on Linux; the standard double-fork daemon
  works with the default `rc` integration (`service nostrfy start`).
- Blossom's `min_free_bytes` check uses `statvfs`, which both systems
  provide; no other platform-specific code is used (the relay itself is
  plain async Rust on top of tokio).

```bash
./target/release/nostrfy --version
```

### Running on port 80

Regular users cannot bind port 80. Either run with `sudo`, or use a higher port such as 8080.

```bash
# Example: run on port 8080 (works for regular users)
./target/release/nostrfy --config nostrfy.toml start
```

---

## 3. The Config File (nostrfy.toml)

Configuration lives in a **TOML** file called `nostrfy.toml`.

### Creating the initial config file

```bash
./target/release/nostrfy --config nostrfy.toml init
```

This generates `nostrfy.toml`. Open it in a text editor and adjust it — every option is commented.

> For the complete option-by-option reference, see [Configuration Reference (CONFIGURATION.md)](CONFIGURATION.md).

### Validating the config

```bash
./target/release/nostrfy --config nostrfy.toml check
```

If anything is wrong, it tells you exactly what. It is strongly recommended to run this before starting.

### Configuration Options

#### `[relay]` — Basic relay information

| Option | Description | Default |
| --- | --- | --- |
| `name` | Relay name (shown to clients via NIP-11) | `nostrfy` |
| `description` | Relay description | A fixed description |
| `pubkey` | Administrator public key (64 hex chars) | empty |
| `contact` | Administrator contact (URL or email) | empty |
| `icon` | Relay icon image URL | empty |
| `post_policy` | URL describing the posting policy | empty |
| `private_key` | The relay's own secret key. **Required for NIP-29 groups** | empty |
| `public_url` | The relay's public URL (e.g. `wss://relay.example.com`). **Set this for NIP-42 auth and friends to work correctly** | empty |
| `livekit_url` | LiveKit server URL (for audio/video rooms) | empty |
| `livekit_api_key` / `livekit_api_secret` | LiveKit API key and secret | empty |
| `enabled_nips` | Explicit allowlist of NIP numbers (empty = all enabled) | empty |
| `disabled_nips` | List of NIP numbers to disable | empty |
| `reject_ephemeral` | When `true`, reject NIP-01 ephemeral events (kinds 20000–29999), except the NIP-mandated kinds (`22242`, `27235`, `28934`/`28935`/`28936`, `24133`, `23194`/`23195`, `24242`, `21059`) | `false` |
| `enabled_git` | When `true`, accept NIP-34 git events (kinds 1617–1633, 30617/30618) and advertise NIP-34. Off by default: the kinds are rejected (`blocked: NIP-34 git events are disabled`) | `false` |
| `require_pow` | Required proof-of-work difficulty in bits (0 = none) | `0` |
| `new_pubkey_min_age_secs` | Reject posts from accounts younger than this (spam defense, 0 = off) | `0` |
| `max_events_per_min_per_pubkey` | Max events a pubkey may publish per minute (0 = unlimited) | `0` |
| `max_groups` | NIP-29 in-memory group store cap (active + deleted markers; `0` = unlimited) | `1000` |
| `require_auth` | Require NIP-42 auth for everything (subscriptions and publishing) | `false` |
| `send_auth_challenge` | Send an AUTH challenge on connect | `true` |
| `enabled_nip78_auth` | Require NIP-42 AUTH before accepting kind 78/30078 events and serve them only to the authenticated owner | `true` |
| `enabled_command_events` | Execute kind:1 operator commands (authored by the admin pubkey `relay.pubkey`) that edit the relay/blossom allow lists, answered with kind:1111 events | `false` |

To generate a secret key, use the `nostrfy genkey` command (see [5. Command Reference](#5-command-reference)).

#### `[server]` — Server settings

| Option | Description | Default |
| --- | --- | --- |
| `host` | Bind address (`0.0.0.0` for all interfaces) | `127.0.0.1` |
| `port` | Port number | `8080` |
| `api_host` | Hostname dedicated to the REST API. When set, only requests with this Host header can use the API (e.g. separate `api.example.com` and `relay.example.com` on the same port) | empty |
| `ws_paths` | Which paths serve the WebSocket endpoint (and the NIP-11 document): `root` (`/` only), `inbox-outbox` (only `/inbox` and `/outbox`), or `all` | `root` |
| `inbox_write_policy` | Write policy for `/inbox`: `any` (the event must carry a `p` tag) or `relay` (the event must `p`-tag the relay's own pubkey) | `any` |
| `outbox_write_policy` | Write policy for `/outbox`: `any` (the event must be authored by the connection's NIP-42-authenticated pubkey) or `relay` (only the relay's own events) | `any` |
| `metrics_enabled` | Serve `/metrics` (Prometheus format) | `true` |

> **Note**: `require_auth = true` combined with `send_auth_challenge = false` locks everyone out — nobody can authenticate. Avoid this combination.

> **Note**: `enabled_nip78_auth = true` (the default) makes kind 78/30078 events private: they require NIP-42 AUTH to publish, and are served only to the authenticated owner (the event author). Unauthenticated subscribers, negentropy syncs and the REST API do not see them. Requires NIP-42 to be enabled; set `enabled_nip78_auth = false` for the legacy public behavior.

> **Note**: `enabled_command_events = true` lets the admin manage the relay/blossom access lists by publishing a kind:1 event signed with the admin pubkey (`relay.pubkey`), e.g. content `/relay deny npub1...` or `/blossom allow npub1...` (the pubkey may carry the `nostr:` URI prefix). The relay executes the command immediately (persisted like `nostrfy relay allow/deny`), and answers with a kind:1111 event signed with `relay.private_key`, tagged `e` to the command and `p` to the admin — served publicly, so the result is visible even when NIP-42 is enabled. Only the admin can issue commands. Off by default.

#### `[rpc]` — NIP-86 management RPC

| Key | Description | Default |
| --- | --- | --- |
| `management_port` | Legacy management port (0 = disabled) | `0` |
| `management_host` | Bind address for the management port | `127.0.0.1` |
| `management_token` | Bearer token for the management API | empty |
| `admin_pubkey` | Administrator public key for NIP-98 auth | empty |

#### `[limits]` — Limits

| Option | Description | Default |
| --- | --- | --- |
| `max_connections` | Maximum concurrent connections | `10000` |
| `max_connections_per_ip` | Max connections per source IP (0 = unlimited) | `64` |
| `max_ws_message_bytes` | Max bytes per WebSocket message/frame | `1048576` (1 MB) |
| `socket_recv_buffer_kb` | Per-connection kernel receive buffer (KiB, `0` = kernel default; the kernel may double the value). Larger values let a fast publisher's burst absorb into one batch while the relay commits it (higher ingest throughput); the buffer only uses real memory while data is queued, so idle connections cost nothing. The send buffer stays 16 KiB | `64` |
| `max_filters` | Max filters per REQ | `20` |
| `max_subscriptions` | Max subscriptions per connection | `20` |
| `max_limit` | Ceiling for the REQ `limit` | `500` |
| `max_count` | Ceiling for COUNT aggregation | `2000` |
| `max_sub_id_len` | Max subscription id length | `64` |
| `max_content_bytes` | Max event content length in **characters** (not bytes — non-ASCII text is fine) | `65536` |
| `max_tags` | Max tags per event | `2000` |
| `max_tag_value_bytes` | Max bytes per tag value | `1024` |
| `max_created_at_future_secs` | How many seconds of future timestamps are tolerated | `3600` |
| `max_neg_items` | Max records per NIP-77 negentropy sync | `100000` |
| `max_out_queue_bytes` | Per-connection outgoing queue cap (bytes; `0` = unlimited) | `262144` |
| `ws_idle_timeout_secs` | Close idle connections after this many seconds (0 = off) | `300` |
| `http_read_timeout_secs` | Seconds to complete an HTTP request head (0 = disabled; slow-loris defense, applies to WS upgrades too) | `30` |
| `max_connections_per_sec_per_ip` | Max new connections per second per source IP (0 = unlimited) | `0` |
| `max_req_response_bytes` | Byte budget for one REQ response (0 = unlimited; over it the subscription is closed with `CLOSED`) | `33554432` (32 MiB) |
| `max_sub_bytes` | Total subscription filter bytes per connection | `524288` |
| `group_late_publish_secs` | Reject NIP-29 group events older than this (0 = off) | `604800` (7 days) |
| `max_api_concurrent` | Max concurrent REST API requests | `32` |
| `max_api_limit` | Ceiling for the API `limit` parameter (0 = unlimited) | `500` |
| `max_api_offset` | Ceiling for the API `offset` parameter (0 = unlimited) | `10000` |
| `max_api_search_bytes` | Max `search` bytes for the API (0 = unlimited) | `1024` |
| `live_batch_interval_ms` / `live_batch_size` | Live fan-out batching (ms / events) | `10` / `64` |
| `live_buffer` | Live fan-out queue size | `65536` |

#### `[database]` — Database

| Option | Description | Default |
| --- | --- | --- |
| `path` | Database directory | `./data` |
| `max_dbs` / `max_readers` | Internal LMDB settings (usually leave as-is) | `32` / `128` |
| `map_size` | Minimum memory-map size (bytes) | 1 GB |
| `max_map_size` | Memory-map ceiling (bytes). **Raise this if you hit the "map is full" error** | 1 TB |
| `purge_interval_secs` | Interval for purging NIP-40 expired events | `300` |
| `search_index` | Enable the NIP-50 full-text index | `true` |
| `reader_threads` | Threads serving WebSocket REQ/COUNT/NEG scans (parallelize query serving across cores; LMDB read transactions never take the write lock) | `2` |
| `max_indexed_words` | Words indexed per event for search | `32` |
| `db_buffer_size` | Initial per-connection WebSocket buffer (bytes, grows on demand) | `2048` |
| `db_request_timeout_secs` | Database request timeout (0 = wait forever) | `30` |
| `max_db_queue_msgs` / `max_db_queue_events` | Overload protection when the DB queue backs up | `4096` / `262144` |

#### `[daemon]` — Daemon settings

| Option | Description | Default |
| --- | --- | --- |
| `pid_file` | PID file path | `./nostrfy.pid` |
| `log_file` | Log file path | `./nostrfy.log` |
| `stats_file` | Statistics file path | `./nostrfy.stats.json` |
| `stats_interval_secs` | Statistics write interval | `5` |
| `max_log_size_bytes` | Log rotation size (0 = no rotation) | 50 MB |
| `max_log_files` | Number of rotated log files to keep | `5` |

#### `[access]` — Access control (also changeable at runtime via NIP-86)

| Option | Description |
| --- | --- |
| `restrict_relay` | `true` = only allow-listed pubkeys may read and post (the lists are managed at runtime, see below) |
| `blocked_kinds` | Event kinds to reject |
| `allowed_kinds` | Kind allowlist. When non-empty, only these kinds are accepted |
| `blocked_ips` | IP addresses to refuse connections from |

> **Note**: The pubkey allow/deny lists are **not** config keys — they live in the relay database and are managed with `nostrfy relay allow/deny` (see [Section 7](#7-nip-86-management-api) / the blossom-style CLI), or at runtime via command events (`/relay allow|deny`, `/blossom allow|deny`). A denied pubkey is always rejected when **publishing**, even with `restrict_relay = false`, and is **never served either**: subscriptions (REQ), COUNT and negentropy syncs are refused with `restricted:`, and live events stop being delivered to its connections — immediately, without disconnecting them. With `restrict_relay = true`, reading is narrowed to allow-listed pubkeys too (anonymous connections are refused as well). The admin pubkey (`relay.pubkey`) and the relay's own pubkey (`relay.private_key`) are exempt from the lists, so the operator can always publish command events and read the replies.

---

## 4. Starting and Stopping

### Start (as a daemon)

```bash
./target/release/nostrfy --config nostrfy.toml start
# => nostrfy started (pid 12345)
```

### Start (foreground, in the terminal)

```bash
./target/release/nostrfy --config nostrfy.toml start --foreground
```

### Stop

```bash
./target/release/nostrfy --config nostrfy.toml stop
# => stopping nostrfy (pid 12345)
# => nostrfy stopped
```

### Restart (re-reads the config)

```bash
./target/release/nostrfy --config nostrfy.toml restart
```

### Health check

```bash
curl http://127.0.0.1:8080/health
# => {"status":"ok"}
```

### NIP-11 information document

```bash
curl -H "Accept: application/nostr+json" http://127.0.0.1:8080/
```

Returns the relay name, supported NIPs, limits, and more as JSON. The `supported_nips` list is dynamic — see [Section 8](#8-supported-nips) for what controls it.

### Reload the config without replacing the process

After editing the config file, a **SIGHUP** reloads it without a full restart:

```bash
# The PID is written to nostrfy.pid
kill -HUP $(cat nostrfy.pid)
```

> Some settings are fixed at startup and are **not** changed by a reload (`api_host`, `ws_paths`, `metrics_enabled`, LiveKit settings, `private_key`, ...). Use `restart` for those; the log warns you when this applies.

---

## 5. Command Reference

All commands accept `--config <path>` (default: `nostrfy.toml`).

| Command | Description |
| --- | --- |
| `nostrfy init` | Write a default `nostrfy.toml` and exit. The file is created `0600` — it will hold secrets later (the private key, S3 keys, the management token) |
| `nostrfy genkey` | Generate a secret key for NIP-29 groups and write it into `relay.private_key`. Asks for confirmation (y/N) if a key already exists. Also prints the public key (the NIP-11 `self`). The config file is restricted to `0600` after the write (it now contains a secret) |
| `nostrfy check` | Validate the config file (run before starting) |
| `nostrfy start` | Start as a daemon (`--foreground` to run in the terminal) |
| `nostrfy stop` | Stop the running daemon |
| `nostrfy restart` | Stop and start again (re-reads the config) |
| `nostrfy stats` | Show live statistics |
| `nostrfy blossom allow <pubkey>` / `deny <pubkey>` / `list` | Manage the Blossom upload allowlist (persisted in LMDB; the running relay applies it on SIGHUP) |
| `nostrfy relay allow <pubkey>` / `deny <pubkey>` / `list` | Manage the relay pubkey allow/deny lists (persisted in LMDB; a denied pubkey is always rejected when publishing and never served when reading; the running relay applies changes on SIGHUP) |
| `nostrfy upgrade [version]` | Update the relay binary to the latest GitHub release, or to the given version. Downloads the asset for this platform (`nostrfy-linux-x86_64`, `-aarch64` or `-freebsd-x86_64`), verifies it runs (`--version` probe) and atomically replaces the binary — a crash mid-upgrade keeps the old binary. Never downgrades a newer local build unless a version is given explicitly; `--force` reinstalls the current version. A running daemon keeps the old binary until `nostrfy restart` |

### Inbox/outbox subscription filters

nostrfy extends the REQ filter syntax with two convenience keys for the inbox/outbox routing model (a nostrfy extension — not part of any NIP):

- `"outbox": "<pubkey>"` — expands to `"authors": ["<pubkey>"]`: only events **authored by** the pubkey (stored and live).
- `"inbox": "<pubkey>"` — expands to `"#p": ["<pubkey>"]`: only events **addressed to** the pubkey (mentions, replies, zaps and DMs that `p`-tag it).

Values may be 64-hex pubkeys or `npub1...` codes, or arrays of either; an existing `authors`/`#p` key is merged. Both keys work for stored queries, live delivery and `COUNT`, and combine with every other filter field. An invalid pubkey rejects the subscription like any malformed filter:

```jsonc
["REQ", "my-feed", {"outbox": "npub1..."}]
["REQ", "mentions", {"inbox": "npub1...", "kinds": [1, 7]}]
```

The inbox/outbox endpoints are also write-restricted: `/outbox` accepts only events authored by the connection's NIP-42-authenticated pubkey (`server.outbox_write_policy = "any"`) or only the relay's own events (`"relay"`); `/inbox` accepts only events carrying a `p` tag (any recipient, or the relay itself with `server.inbox_write_policy = "relay"`).

---

## 6. REST API

nostrfy provides a read-only REST API at `GET /api/v1/...`.

> If `server.api_host` is set, only requests with that Host header can use the API (e.g. `curl -H "Host: api.example.com" ...`).

### Fetching events

| Path | Description |
| --- | --- |
| `/api/v1/{npub1}/{kind}` | Events of a pubkey, filtered by kind |
| `/api/v1/{note1}` | A single event |
| `/api/v1/{nevent1}` | A single event |
| `/api/v1/{naddr1}` | A specific addressable event |

Example:

```bash
curl "http://127.0.0.1:8080/api/v1/npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc/1"
# => {"events":[...],"count":N,"more":false}
```

### Query / count / kinds / daily / id endpoints

- `GET /api/v1/query` — generic filter query (authors/kinds/e/p/t/d/since/until/search/no_*/sort/limit/offset).
- `GET /api/v1/count` — total count for the same parameters (`{"count": N, "approximate": bool}`).
- `GET /api/v1/{npub1...}/kinds` — per-kind counts for an author, most used first.
- `GET /api/v1/{npub1...}/{kind}/daily?year=&month=` — per-day counts for one month, zero-filled through the last day (e.g. `2026-08-31: 0` even before the 31st).
- `GET /api/v1/ids/{hex}` — a single event by 64-hex id.
- `GET /api/v1/{npub1...}` — the author's latest kind-0 profile.

### Stats / hourly / related / follows / relay kinds

- `GET /api/v1/{npub1...}/stats` — author summary (total, first/last activity, kind breakdown).
- `GET /api/v1/{npub1...}/{kind}/hourly?year=&month=&day=` — 24 per-hour counts for one day, zero-filled.
- `GET /api/v1/ids/{hex}/related` — replies (`#e`) and quotes (`#q`) referencing the event.
- `GET /api/v1/{npub1...}/follows` — the author's latest kind-3 follow list.
- `GET /api/v1/relay/kinds` — the most common kinds on the relay (bounded walk, `approximate` flag).

### Top authors / relay lists

- `GET /api/v1/relay/top-authors` — the most active authors on the relay (bounded walk, `approximate` flag).
- `GET /api/v1/{npub1...}/relays` — the author's latest NIP-65 relay list (kind 10002).

### Monthly counts

`GET /api/v1/{npub1...}/{kind}/monthly` returns per-month event counts (`{"months": [{"month": "2026-08", "count": 4, "approximate": false}], "total": 4}`) for a pubkey + kind, zero-filled over the `since`/`until` range (default: the whole period, from the earliest stored event to now; at most 1200 months).

### Query parameters

| Parameter | Description |
| --- | --- |
| `limit` | Max results (default 100, capped by `max_api_limit`) |
| `offset` | Number of results to skip (pagination) |
| `since` / `until` | Unix timestamp range |
| `sort` | `asc` for oldest-first (default is newest-first) |
| `search` | NIP-50 full-text search |
| `e` / `p` / `t` / `d` | Filter by `#e` / `#p` / `#t` / `#d` tags |

`more: true` means there is more data; increase `offset` to continue.

> **Tip**: Pagination is computed over the *visible* sequence, so hidden events (protected events etc.) never skip or duplicate a page.

> For the full endpoint, parameter, pagination and error reference, see [HTTP REST API Reference (API.md)](API.md).

---

## 7. NIP-86 Management API

NIP-86 is a JSON-RPC API for managing the relay. **Authentication is required.**

### Authentication methods

1. **Bearer token**: set `rpc.management_token` and send `Authorization: Bearer <token>`
2. **NIP-98**: set `rpc.admin_pubkey` and send a NIP-98 auth event (kind 27235) signed by the admin key in `Authorization: Nostr <base64>` (a `payload` tag is required)

### Calling the API

`POST /` with `Content-Type: application/nostr+json+rpc`:

```bash
curl -X POST http://127.0.0.1:8080/ \
  -H "Content-Type: application/nostr+json+rpc" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"method":"supportedmethods","params":[]}'
```

### Methods

| Method | Params | Description |
| --- | --- | --- |
| `supportedmethods` | `[]` | List of supported methods |
| `banpubkey` | `["pubkey", "reason (optional)"]` | Ban a pubkey from posting |
| `unbanpubkey` | `["pubkey"]` | Unban a pubkey |
| `listbannedpubkeys` | `[]` | List banned pubkeys and reasons |
| `allowpubkey` | `["pubkey", "reason (optional)"]` | Add to the allowlist (also un-bans) |
| `unallowpubkey` | `["pubkey"]` | Remove from the allowlist |
| `listallowedpubkeys` | `[]` | List the allowlist |
| `allowkind` / `disallowkind` | `[kind]` | Allow / disallow a kind |
| `listallowedkinds` | `[]` | List allowed kinds |
| `changerelayname` / `changerelaydescription` / `changerelayicon` | `["new value"]` | Change the relay name / description / icon (**persisted to the config file**) |
| `createrole` / `editrole` / `deleterole` | `[id, label, description, color, order]` | NIP-43 role management |
| `assignrole` / `unassignrole` | `["pubkey", "role id"]` | Assign / unassign a role |
| `blockip` / `unblockip` | `["ip", "reason (optional)"]` | Block / unblock an IP (**blocking also drops existing connections**) |
| `listblockedips` | `[]` | List blocked IPs |
| `banevent` / `allowevent` | `["event id", "reason (optional)"]` | Ban / unban an event |
| `listbannedevents` | `[]` | List banned events |
| `listeventsneedingmoderation` | `[]` | Events awaiting moderation (always empty on this relay) |

### Legacy management port

If `rpc.management_port` is set, the legacy REST endpoints are available at `http://<management_host>:<port>/admin/...` (`/admin/info`, `/admin/stats`, `/admin/block_pubkey`, `/admin/allow_pubkey`, `/admin/block_kind`, `/admin/allow_kind`, `/admin/status/{id}`, `/admin/shutdown`). Same authentication.

---

## 8. Supported NIPs

| NIP | Description |
| --- | --- |
| 1 | Basic protocol (events, subscriptions) |
| 9 | Event deletion |
| 11 | Relay information document |
| 13 | Proof of work |
| 17 | Private DMs (kind 14, wrapped in 15; ephemeral wraps 1059/21059 forwarded) |
| 22 | Comments (kind 1111, threaded via the `#e` index) |
| 26 | Delegated event signing |
| 28 | Public chat |
| 29 | Relay-based groups |
| 32 | Labeling (kind 1985, `#l`/`#L` indexed) |
| 33 | Parameterized replaceable events |
| 34 | git stuff (kinds 1617-1633, 30617/30618 — **opt-in** via `relay.enabled_git`, off by default) |
| 40 | Expiration timestamp |
| 42 | Client authentication |
| 43 | Relay access metadata (roles) |
| 45 | Counting results (COUNT / HyperLogLog) |
| 46 | Nostr Connect (ephemeral kind 24133, exempt from `reject_ephemeral`) |
| 47 | Nostr Wallet Connect (ephemeral kinds 23194/23195, exempt from `reject_ephemeral`) |
| 50 | Search capability (full-text, relevance-ordered) |
| 57 | Lightning zaps (kinds 9734/9735, `#z` indexed) |
| 59 | Gift wrap (recipient-only serving) |
| 62 | Request to vanish |
| 65 | Relay list metadata (kind 10002, `#r` indexed) |
| 66 | Relay discovery & liveness (self-publishes kind 30166 when `relay.private_key` is set, refreshed every 12 h) |
| 67 | EOSE completeness hint (incl. the `"auth"` hint with a challenge when AUTH-gated events were withheld) |
| 70 | Protected events |
| 77 | Negentropy syncing |
| 78 | Application-specific data (kind 30078, addressable; **AUTH-gated** — see `relay.enabled_nip78_auth`) |
| 84 | Highlights (kind 9802) |
| 85 | Trusted assertions (kinds 30382/30383/30384, addressable) |
| 86 | Relay management API |
| 87 | Cashu and Fedimint announcements (kinds 38172/38173) |
| 88 | Polls (kinds 1068/1018) |
| 94 | File metadata (kind 1063 — references an externally hosted file) |
| 98 | HTTP auth |
| A3 | Payment targets (kind 10133, replaceable). `draft` with no integer identifier — served but **not** advertised in `supported_nips` (which only holds integers) |

Blossom (BUD-01/02) is not a NIP and is **not** advertised in the NIP-11 document: it is served as a separate file server on the `[blossom]` hostname (see [Section 11](#11-blossom-file-server-media-hosting)), with its own kind-24242 upload authorization.

### Dynamic NIP advertisement

The NIP-11 `supported_nips` list is not static: a NIP is dropped from it when every kind the NIP defines is rejected by the relay's access control. Concretely:

- **`blocked_kinds`** — blocking all kinds of a NIP hides it (e.g. blocking kind `5` hides NIP-09). Blocking only some kinds keeps the NIP (e.g. blocking `9000` but not `9001` keeps NIP-29).
- **`allowed_kinds`** — a NIP's kind is only accepted when listed; a NIP whose kinds are all unlisted is hidden.
- **`reject_ephemeral`** — ephemeral kinds that are not in the NIP-mandated exempt list (`22242`, `27235`, `28934`/`28935`/`28936`, `24133`, `23194`/`23195`, `24242`, `21059`) are rejected, so NIPs relying on them are hidden.
- NIPs without dedicated kinds (11, 13, 26, 33, 40, 45, 50, 67, 70, 77, 86) are always advertised when enabled.

Changes made at runtime — NIP-86 `allowkind`/`disallowkind`, or a `SIGHUP` reload of `reject_ephemeral` — are reflected in the next NIP-11 fetch. `enabled_nips`/`disabled_nips` still require a restart.

---

## 9. NIP-29 Groups

nostrfy supports NIP-29 (relay-based groups): closed chat spaces where only members can write.

### Enabling groups

1. Run `nostrfy genkey` to set `relay.private_key` (**required** — group metadata is not generated without it)
2. `restart` the relay

### How groups work (overview)

| Event | Description |
| --- | --- |
| `kind:9007` | Create group (the creator becomes the admin) |
| `kind:9000` / `9001` | Add member (with roles) / remove member |
| `kind:9002` | Edit metadata (name, description, public/private, ...) |
| `kind:9005` | Delete event (moderation) |
| `kind:9008` | Delete group |
| `kind:9009` | Create invite code |
| `kind:9010` | Update pin list |
| `kind:9021` / `9022` | Join request / leave request |

From these moderation events, the relay generates the following **relay-signed snapshots** (used by clients for display):

- `kind:39000` — group metadata (name, visibility settings, ...)
- `kind:39001` — admin list
- `kind:39002` — member list
- `kind:39005` — pinned events

### Group visibility settings

| Tag | Meaning |
| --- | --- |
| `private` | Only members can read messages |
| `restricted` | Only members can write |
| `hidden` | Metadata is hidden from non-members |
| `closed` | Join requests are not auto-approved (invite codes required) |
| `livekit` | The group has a LiveKit audio/video room |

### Subgroups

Groups can be hierarchical (`parent` / `child` tags). Cycles are rejected automatically.

---

## 10. LiveKit (Audio/Video Rooms)

With a LiveKit server configured, groups can have audio/video chat rooms.

1. Set `relay.livekit_url`, `relay.livekit_api_key`, and `relay.livekit_api_secret`
2. Add the `livekit` tag to the group's metadata (via an admin's 9002 edit)
3. Clients fetch a JWT from `/.well-known/nip29/livekit/<group-id>` with NIP-98 auth

```bash
# Support check (204 means enabled)
curl -i http://127.0.0.1:8080/.well-known/nip29/livekit
```

---

## 11. Blossom File Server (Media Hosting)

nostrfy can act as a [Blossom](https://github.com/hzrd149/blossom) blob server: clients upload files addressed by their SHA-256 hash, and the relay serves them back. Like the REST API, the Blossom server lives on a dedicated hostname on the same port.

### 11.1 Configuration

```toml
[blossom]
host = "media.example.com"          # required — enables the feature
storage = "local"                   # "local" or "s3"
local_path = "./data/images"        # local storage root
max_upload_bytes = 20971520         # 20 MiB
min_free_bytes = 33554432         # refuse uploads when the disk has less free space
restrict_uploads = false            # only allow-listed pubkeys may upload


# For S3 / Cloudflare R2:
s3_endpoint = "https://<account>.r2.cloudflarestorage.com"
s3_region = "auto"
s3_bucket = "nostr-media"
s3_access_key = "..."
s3_secret_key = "..."
```

Point `media.example.com` (and only that hostname) at the same port in your reverse proxy, then restart (`nostrfy restart`). `GET /` on that host answers with the Blossom server info document.

### 11.2 Storage layout

Both backends use the `bucket/{npub1xxx}/{file}` hierarchy: every upload is stored under the uploader's npub directory, keyed by the file's SHA-256.

- **local**: `<local_path>/<npub1...>/<sha256>` (plus a `<sha256>.meta.json` descriptor)
- **s3 / R2**: objects `<npub1...>/<sha256>` in the configured bucket

### 11.3 Endpoints

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/` | — | Blossom server info |
| `GET` / `HEAD` | `/<sha256>[.ext]` | — | Fetch / probe a blob (`.ext` is advisory); `GET` supports RFC 7233 byte ranges (206 / `accept-ranges: bytes`) |
| `PUT` | `/upload` | kind 24242 (`t=upload`, `x=<sha256>`, `expiration`) | Upload a blob; returns 201 + the descriptor |
| `HEAD` | `/upload` | kind 24242 (`t=upload`, `x=<sha256>`, `expiration`) | BUD-06 pre-flight — would the upload be accepted? Uses `X-SHA-256` / `X-Content-Length` / `X-Content-Type` headers (400 malformed / 411 missing length / 413 too large) |
| `PUT` | `/media` | kind 24242 (`t=media`, `x=<sha256>`, `expiration`) | BUD-05 media upload (stored verbatim — no optimization); returns 201 + the descriptor |
| `HEAD` | `/media` | kind 24242 (`t=media`, `x=<sha256>`, `expiration`) | BUD-05 pre-flight — would the upload be accepted? Uses `X-SHA-256` / `X-Content-Length` / `X-Content-Type` headers (400 malformed / 411 missing length / 413 too large) |
| `GET` | `/list/<pubkey>` | — | Blobs uploaded by a pubkey (hex), sorted by `uploaded` descending; supports `cursor` (the sha256 of the last entry of the previous page) and `limit` |
| `DELETE` | `/<sha256>` | kind 24242 (`t=delete`, `x=<sha256>`, `expiration`) | Delete a blob (uploader only) |

- `PUT /upload` returns **201** when the blob was newly stored and **200** when it already exists (BUD-02).
- Authorization tokens are accepted in the spec's **Base64url (no padding)** form and in the padded standard form (BUD-11).
- The optional `X-SHA-256` request header is verified against the actual bytes: a mismatch returns **409** (BUD-02).
- The CORS pre-flight accepts the BUD-05/06 headers (`X-SHA-256`, `X-Content-Type`, `X-Content-Length`), so browser clients like nostter can upload to `/media`.

Uploads and deletes authenticate with a Nostr auth event (kind 24242, `server` tag naming the Blossom host), sent as `Authorization: Nostr <base64>`. Per BUD-11 the token must carry an `expiration` tag set to a unix timestamp in the future, the `t` verb matching the endpoint (`upload` / `delete`), and — for upload and delete — an `x` tag with the blob's sha256.

The descriptor `url` includes the MIME-derived extension (e.g. `https://media.example.com/<sha256>.png`; unknown types get `.bin`), like the Blossom spec's examples. The extension is advisory: the file is served by its hash alone, and `/<sha256>.<ext>` (any extension) resolves to the same blob.

### 11.4 Example

```bash
# Server info
curl https://media.example.com/

# Upload (auth event from your Blossom client, e.g. via `nak` or the nostr-tools blossom helper)
curl -X PUT -H "Authorization: Nostr <auth>" -H "Content-Type: image/png" --data-binary @photo.png https://media.example.com/upload

# Fetch
curl https://media.example.com/<sha256>

# List the uploads of a pubkey
curl https://media.example.com/list/<pubkey-hex>

# Delete (auth event with t=delete and x=<sha256>)
curl -X DELETE -H "Authorization: Nostr <auth>" https://media.example.com/<sha256>
```

### 11.5 Restricting uploads to an allowlist

Set `restrict_uploads = true` in the `[blossom]` section to allow only listed pubkeys to upload:

```toml
[blossom]
host = "media.example.com"
restrict_uploads = true
```

The allowlist itself is **not** stored in the config file — it lives in the relay database (LMDB) and is managed with dedicated commands (no restart needed; the running daemon is reloaded automatically):

```sh
nostrfy blossom allow npub1...          # allow a pubkey (npub1... or hex)
nostrfy blossom deny npub1...          # revoke a pubkey
nostrfy blossom list                  # show the list and restrict_uploads
```

Uploads from unlisted pubkeys are rejected with `403`. The list survives restarts and is shared with the running daemon via a database reload (SIGHUP). It is stored under a fixed key of the existing `access` table — no new LMDB table is created, so databases from older versions remain compatible.

### 11.6 Notes

- Files are served with `ETag`, `Cache-Control: immutable` and the stored content type.
- Blobs never touch the relay database; the relay's WebSocket / REST API performance is unaffected.
- The sha256 → owner mapping is persisted in the relay database (LMDB): the relay restarts instantly, lookups read the mapping directly from the database (no in-memory index, no startup scan), and existing files keep working.
- **Automatic migration**: on the first start after an upgrade, the relay rebuilds the mapping from blobs stored by older versions (a background scan — the table itself is created instantly, and later restarts skip the migration via a marker). No manual step is needed.
- **All database upgrades are automatic**: every LMDB table is opened-or-created at startup (instant, non-destructive), and the one-time data migrations (access lists, Blossom mapping) run by themselves — see [CONFIGURATION.md](CONFIGURATION.md#upgrades-are-automatic-and-instant).

---

## 11b. Running Multiple Instances

nostrfy supports several independent relays on one server (different ports). Each instance needs its **own**:

- `server.port` — the listen port
- `[daemon] pid_file` / `log_file` / `stats_file` — **shared values make the second instance refuse to start with `already running`**
- `database.path` — an independent database per instance
- `api_host` / `blossom.host` — a distinct hostname per instance when the host split is used

Example:

```toml
# /etc/nostrfy/a.toml — instance A
[server]
port = 8080

[database]
path = "/var/lib/nostrfy-a"

[daemon]
pid_file = "/var/run/nostrfy-a.pid"
log_file = "/var/log/nostrfy-a.log"
stats_file = "/var/lib/nostrfy-a/stats.json"
```

```toml
# /etc/nostrfy/b.toml — instance B
[server]
port = 8081

[database]
path = "/var/lib/nostrfy-b"

[daemon]
pid_file = "/var/run/nostrfy-b.pid"
log_file = "/var/log/nostrfy-b.log"
stats_file = "/var/lib/nostrfy-b/stats.json"
```

Each instance is managed with its own config: `nostrfy --config /etc/nostrfy/a.toml start` etc.

## 12. Logs and Statistics

### Logs

The daemon writes to `daemon.log_file`. When the file grows past `max_log_size_bytes`, it rotates automatically (`nostrfy.log.1`, `nostrfy.log.2`, ... up to `max_log_files` generations).

```bash
# Follow the log
tail -f nostrfy.log
```

The log level is controlled by the `RUST_LOG` environment variable (e.g. `RUST_LOG=debug`).

### Statistics

```bash
./target/release/nostrfy stats
```

Or over HTTP:

```bash
curl http://127.0.0.1:8080/relay/stats
```

Shows connections, events received/accepted/rejected, DB size, and more.

### Prometheus metrics

```bash
curl http://127.0.0.1:8080/metrics
```

Available when `metrics_enabled = true`.

---

## 13. Reloading Configuration (SIGHUP)

After editing the config file, reload it without a restart:

```bash
kill -HUP $(cat nostrfy.pid)
```

Settings that take effect on reload: relay name/description, limits (except the HTTP-layer ones below), NIP toggles (partially), NIP-40 on/off, API concurrency, ...

Settings that require a **restart**: `private_key`, `api_host`, `metrics_enabled`, LiveKit settings, `enabled_nips`/`disabled_nips`, and the HTTP-layer limits (`max_connections`, `http_read_timeout_secs`, `max_connections_per_sec_per_ip` — they shape the accept loop built at startup). The log warns when a change needs a restart.

---

## 14. Large-Scale Deployments

The relay is designed to scale to hundreds of thousands of connections
on a single host (the live delivery wakes only the subscribers that can
match an event, and the per-connection memory is kept small). Pushing
into the millions requires host-level tuning:

| Setting | Value | Why |
| --- | --- | --- |
| `ulimit -n` / systemd `LimitNOFILE` | ≥ 2× the target connections (+1000) | Every connection holds an fd |
| `net.core.somaxconn` | ≥ 1024 | Pending accept queue for connection bursts |
| `net.ipv4.tcp_mem` / `net.ipv4.tcp_rmem` / `tcp_wmem` | tuned to the host RAM | The relay sets 16 KiB per socket direction; the kernel defaults must still cover the aggregate |
| `net.ipv4.tcp_fin_timeout` | low (e.g. 10) | Reclaims TIME_WAIT sockets faster |
| `vm.overcommit_memory` | 1 or 2 | The LMDB map is a large sparse virtual reservation (see `database.max_map_size`) |

On FreeBSD the same knob is `sysctl kern.maxfiles` / `kern.maxfilesperproc`
plus `ulimit -n` (the default 1024 per-process limit must be raised for
any serious connection count), and `kern.ipc.somaxconn` replaces
`net.core.somaxconn`. The `socket_recv_buffer_kb` setting applies like on
Linux; note that FreeBSD does not double the requested `SO_RCVBUF`
value, so the actual receive buffer equals the configured size.

Per-connection kernel memory is ~32 KiB (16 KiB per direction, set by
the relay) and user space ~10 KiB (the task, the connection state, the
WebSocket buffer), so a million connections need roughly 40 GiB of
kernel + user memory on top of the database. The WebSocket reader pool
has two threads; a single heavy REQ no longer stalls every query.

### Throughput (events per second)

Event ingestion is bound by two costs: the Schnorr signature check
(about 30-50 µs per event) and the synchronous disk flush the LMDB
writer performs after every commit batch. Both are tunable in
`nostrfy.toml`:

| Setting | Value | Why |
| --- | --- | --- |
| `database.disabled_fsync = true` | `false` | The dominant ingest cost is the fsync after each commit batch. With `disabled_fsync` the writer commits into the OS page cache (microseconds) and the kernel flushes shortly after; a power loss loses only the writes since the last flush. Start here. |
| CPU cores | ≥ 8 vCPU | The batch `EVENT` path verifies every signature in parallel across the cores (see below) before the cheap checks run |

Starting the relay with `RUST_LOG=nostrfy=debug` shows the config the
instance is actually using, and real-world tuning should be measured,
not guessed; the per-connection drop pattern (many clients posting
events) is what a relay sees in production.

**How the parallel signature check works.** When a WebSocket client's
pending EVENTS are flushed, the batch is verified before the relay
decides acceptance: every signature in the batch is checked at once on a
pool of worker threads (`verify_signatures_parallel`, capped at 8
threads; batches under 16 events verify inline). Each event's cheap
checks (size, kind, PoW, tags, NIP-40) still run first, so the reject
reason text is identical to the sequential path — only the Schnorr work,
the only expensive per-event operation, is spread across cores. Under a
multi-core build the ingest ceiling approximately multiplies by the
worker count; a single-threaded build stays sequential and the setting
changes nothing.

The remaining ingest costs are cheap by design: the per-event metadata
header (`database.meta_index`) is one small index write, the NIP-50 word
index (`database.search_index`) is off by default per event and can be
disabled entirely on write-heavy instances, and the writer merges every
deferred EVENTS batch waiting in its queue into one commit (one fsync,
or none with `disabled_fsync`). Event cloning for the writer and the
broadcast are the only per-event allocations left; the live-delivery
subscribers are matched by the reader pool without the writer's lock.

## 15. When You Are Stuck

See [Troubleshooting (TROUBLESHOOTING.md)](TROUBLESHOOTING.md) for common errors and their fixes.

Absence filters: `no_p`, `no_e`, `no_t` and `no_d` exclude events carrying that tag before pagination (e.g. `no_p=true` keeps only top-level posts — mentions, replies and DMs are dropped).