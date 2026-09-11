# nostrfy Troubleshooting

This page collects the errors you are most likely to meet while running nostrfy, together with step-by-step fixes.

**Three things to check first**:

1. `nostrfy check` validates your config (9 out of 10 errors are config mistakes)
2. `tail -f nostrfy.log` shows the log (the cause of the error is almost always there)
3. `nostrfy restart` restarts the daemon cleanly

---

## Table of Contents

1. [Cannot Start](#1-cannot-start)
2. [Cannot Connect / Behaves Strangely](#2-cannot-connect--behaves-strangely)
3. [Errors When Publishing](#3-errors-when-publishing)
3b. [Blossom File Server](#3b-blossom-file-server)
4. [Search, Groups, Auth](#4-search-groups-auth)
5. [Database and Disk](#5-database-and-disk)
6. [Daemon Operation](#6-daemon-operation)
7. [Still Not Solved?](#7-still-not-solved)

---

## 1. Cannot Start

### 1-1. `error: cannot bind to 0.0.0.0:80: Permission denied`

**Cause**: Port 80 can only be bound by root.

**Fix**: Run with `sudo`, or change the port to something like 8080.

```bash
# Change port = 8080 in the config file, then:
./target/release/nostrfy --config nostrfy.toml start
```

### 1-2. `error: cannot bind to ...: Address already in use`

**Cause**: Another process (an old nostrfy or a different server) is already using the port.

**Fix**:

```bash
# See what is using the port
ss -tlnp | grep :8080

# If nostrfy is running, restart it
./target/release/nostrfy --config nostrfy.toml restart

# If it is another process, stop it and retry
```

### 1-3. `already running (pid 1234); use 'nostrfy stop' or 'nostrfy restart'`

**Cause**: nostrfy is already running; `start` refuses to start a second instance.

**Fix**: Use `nostrfy restart`, or just use the running instance.

### 1-4. `nostrfy stop` hangs / `did not stop in time`

**Cause**: The daemon is stuck or not responding.

**Fix**:

```bash
# Check the process
ps aux | grep nostrfy

# If it really will not stop, force-kill it
kill -9 <PID>
# Remove a stale pid file if present
rm -f nostrfy.pid
```

### 1-5. `error: invalid nostrfy.toml: TOML parse error`

**Cause**: The config file is not valid TOML. Common mistakes: forgetting quotes around a string, or writing the same key twice.

**Fix**: The error message includes a line number. Check and fix that line.

```toml
# Correct examples
name = "my relay"        # strings are quoted with "
port = 8080              # numbers are plain
enabled_nips = [1, 50]   # lists are wrapped in [ ]
```

### 1-6. `error: cannot read nostrfy.toml: No such file or directory`

**Cause**: The config file does not exist.

**Fix**:

```bash
./target/release/nostrfy --config nostrfy.toml init
```

### 1-7. `error: relay.private_key is not a valid secp256k1 secret key`

**Cause**: `relay.private_key` is not a valid 64-character hex key.

**Fix**: Run `nostrfy genkey` to generate a correct key (or set `private_key = ""`).

### 1-8. Lots of warnings in the log at startup

`[WARN]` log lines tell you about configuration problems. The main ones:

| Warning | Meaning and fix |
| --- | --- |
| `relay.public_url is empty and server.host is "0.0.0.0"...` | `public_url` is not set. **NIP-42 auth, NIP-62 vanish and NIP-98 admin auth will not work.** Set `wss://your-public-url` |
| `relay.private_key is empty while NIP-29 is enabled...` | Groups need a secret key. Run `nostrfy genkey` |
| `unknown config key [relay].software is ignored` | An unused legacy key (or a typo) in the config. Check the key name |
| `unknown config section [serve] is ignored` | A typo in a section name (e.g. `[serve]` instead of `[server]`). Fix it |
| `relay.require_auth is true but relay.send_auth_challenge is false...` | This combination locks everyone out. Change one of the two |
| `relay.require_pow = 64 ... practically unmineable` | The PoW requirement is so high nobody can post. Lower `require_pow` |
| `livekit_url is set but livekit_api_key/livekit_api_secret are empty` | LiveKit credentials are incomplete |

---

## 2. Cannot Connect / Behaves Strangely

### 2-1. Client gets `connection refused`

**Cause**: The relay is not running, or a firewall is blocking the port.

**Fix**:

```bash
# Is the relay up?
curl http://127.0.0.1:8080/health

# From outside (using the server's IP/port)
curl http://YOUR_SERVER_IP:8080/health

# Check the firewall (example: ufw)
sudo ufw status
# Open the port if needed
sudo ufw allow 8080
```

### 2-2. External clients cannot connect, local ones can

**Cause**: `server.host` is still `127.0.0.1` (the default), which only accepts local connections.

**Fix**: Set `host = "0.0.0.0"` in the config and restart.

### 2-3. Cannot connect through a Cloudflare tunnel

When using Cloudflare Tunnel:

- The relay runs plain HTTP; Cloudflare terminates TLS, so clients use `wss://`. Set `public_url = "wss://..."` on the relay (this makes NIP-42 auth work)
- Cloudflare adds an `X-Forwarded-Proto` header. nostrfy treats `ws`/`wss`/`http`/`https` values the same, so no extra configuration is normally needed

### 2-4. `error: message too large` and the connection closes

**Cause**: A single message exceeds `max_ws_message_bytes` (default 1 MB).

**Fix**: Raise `limits.max_ws_message_bytes` if you need larger events — but also check the client's own limits.

### 2-5. `too many subscriptions` / `too many filters` errors

**Cause**: The per-connection caps were reached (subscriptions default 20, filters default 20).

**Fix**: Raise `limits.max_subscriptions` / `limits.max_filters` (and check the client settings).

### 2-6. New connections are refused under load

**Cause**: `max_connections` (default 10000) was reached, the per-IP cap (`max_connections_per_ip`, default 64) kicked in, or the per-second connection rate limit (`max_connections_per_sec_per_ip`) refused the burst. The caps apply to every connection — WebSocket and plain HTTP alike.

**Fix**: Review and adjust the settings. `max_connections_per_ip = 0` disables the per-IP cap (be careful about floods); `max_connections_per_sec_per_ip = 0` disables the rate limit. These three settings require a restart.

### 2-7. Connections drop after a while

**Cause**: If `ws_idle_timeout_secs` is set, idle connections are closed. Healthy clients answer the relay's PING with a PONG and stay connected; only dead peers are reaped.

**Fix**: This is intentional — the default is `300` seconds (idle connections are reaped after 5 minutes). Set `ws_idle_timeout_secs = 0` to disable it entirely.

---

### 2-7a. A subscription ends with `CLOSED ... response too large`

**Cause**: The stored events of one REQ exceeded `max_req_response_bytes` (default 32 MiB) — the response is delivered in bounded chunks as the socket drains, and beyond the budget the subscription is closed so a slow reader cannot pin unbounded memory. This only happens with very large events or very wide filters.

**Fix**: Narrow the filter (tighter `since`/`until`, a lower `limit`) or raise `max_req_response_bytes` (0 disables the budget).

---

### 2-8. A NIP is missing from the NIP-11 `supported_nips` list

**Cause**: The advertised list is dynamic — a NIP is hidden when all the kinds it defines are rejected: they are all in `blocked_kinds`, none of them is in `allowed_kinds`, or they are ephemeral kinds rejected by `reject_ephemeral` (only the exempt kinds `22242`, `27235`, `28934`/`28935`/`28936`, `24133`, `23194`/`23195`, `24242`, `21059` are forwarded). NIP-29/43/66 additionally require `relay.private_key` (their relay-signed events cannot be produced without it) and NIP-86 requires `rpc.management_token` or `rpc.admin_pubkey`. Runtime access changes via NIP-86 (`allowkind`/`disallowkind`) apply immediately; NIPs without dedicated kinds (11, 13, 26, 33, 40, 45, 50, 67, 70, 77) are always advertised when enabled.

**Fix**: Check the active access lists — NIP-86 `listallowedkinds` shows the kind allowlist (use `disallowkind` to add a kind to the blocklist, `allowkind` to remove it), and `GET /` shows the effective `supported_nips` immediately. Remove the blocking kind or the `reject_ephemeral` setting, then `SIGHUP` or re-issue the NIP-86 call.

---

## 3. Errors When Publishing

### 3-1. `OK` is `false` — error reference

When publishing fails, the 4th element of the `OK` message explains why. The common ones:

| Error | Meaning and fix |
| --- | --- |
| `invalid: signature verification failed` | The event signature is invalid (possibly a broken client key) |
| `invalid: content too large` | Content exceeds `max_content_bytes` (default 64K characters). Shorten it or raise the limit |
| `invalid: too many tags` | More tags than `max_tags` (default 2000) |
| `invalid: tag value too large` | A tag value exceeds `max_tag_value_bytes` (default 1 KB) |
| `invalid: event creation date is in the future` | Timestamp too far in the future (beyond `max_created_at_future_secs`) |
| `mute: event contains secret key material` | The content or tags contain an nsec-looking string. **Never post secret keys.** Remove the string and the event is accepted |
| `duplicate: event already stored` | The same event is already stored (normal) |
| `blocked: pubkey not allowed` | The pubkey is banned (`banpubkey`) or outside the allowlist |
| `blocked: kind not allowed` | This kind is disallowed |
| `rate-limited: too many events` | The pubkey exceeded `max_events_per_min_per_pubkey` (sliding 60-second window). Wait a minute and retry, or raise/disable the limit |
| `blocked: event has been banned` | The event id is banned |
| `blocked: event has been deleted` | Re-publishing a deleted event |
| `invalid: event has expired` | The NIP-40 expiration has passed |
| `pow: difficulty requirement not reached` | The event does not meet `require_pow` |
| `auth-required: ...` | Authentication is required (when `relay.require_auth` is on) |
| `restricted: ...` | Access restrictions (groups, account age, ...) |
| `restricted: your account is too new` | The account was created within `new_pubkey_min_age_secs`. Wait and retry |
| `restricted: unknown group` | The group does not exist (create it first) |
| `restricted: you are not an admin of this group` | Only admins can send moderation events |
| `restricted: this group is closed` | The group is `closed`; join requests without an invite code are not honored |
| `invalid: event is too old for this group` | The event is older than `group_late_publish_secs` |

### 3-2. Events are stored but do not show up in subscriptions

Possible causes:

1. **NIP-70 protected events** (with a `-` tag) are only delivered to authenticated clients. If the subscriber is not authenticated, it cannot see them (by spec)
2. **NIP-29 private-group** events are only delivered to members
3. **NIP-40 expired** events are not delivered

### 3-3. Old group events are rejected

Group posts have a time limit (`group_late_publish_secs`, default 7 days). Older events are rejected with `invalid: event is too old for this group`.

---

## 3b. Blossom File Server

### 3b-1. Upload fails with `401`

The upload authorization event (kind 24242) was rejected. Check that:
- the token's `expiration` tag is **present** and set to a unix timestamp in the future (BUD-11 makes it mandatory),
- for upload/media/delete the token carries an **`x` tag with the blob's sha256** (also mandatory per BUD-11),
- the `server` tag (when present) names exactly the configured `blossom.host` (hostname only, no scheme/path),
- the token was signed within the last 10 minutes (a freshness window against replay),
- and the signing key is the uploader's own.

### 3b-2. Upload fails with `403`

`blossom.restrict_uploads = true` is set and the pubkey is not on the allowlist — add it with `nostrfy blossom allow npub1...` (the daemon reloads automatically). If the list looks wrong, `nostrfy blossom list` shows it.

### 3b-2a. Upload fails with `409`

The client sent an `X-SHA-256` header that does not match the actual request body (the declared hash was computed over different bytes — e.g. the file changed between hashing and sending). Clients may omit the header entirely.

### 3b-3. `GET /` on the media host serves the NIP-11 document instead of the Blossom server info

The request did not reach the relay with the Blossom Host header. Point `media.example.com` (or whatever `blossom.host` is set to) at the same port in the reverse proxy, then `nostrfy restart`.

### 3b-4. A blob 404s right after upload

The file is content-addressed by its SHA-256: fetch it via the exact hash returned in the upload response (`/<sha256>` or `/<sha256>.<ext>`). A mismatch means the client requested a different hash than the bytes it sent.

## 4. Search, Groups, Auth

### 4-1. Search returns 0 results / unexpected results

nostrfy search matches **whole words**. Note that:

- `search = "rust"` matches events containing the word "rust", but `"ru"` does NOT match "rust" as a substring
- Only words in the event content are searched
- If `search_index = false`, search still works but is slower
- If NIP-50 is disabled (`disabled_nips = [50]`), `search` is ignored (a NOTICE is sent)

### 4-2. Group metadata (39000-39005) is not generated

**Cause**: `relay.private_key` is not set. Group snapshots are signed by the relay's own key, so without it nothing is generated.

**Fix**:

```bash
./target/release/nostrfy --config nostrfy.toml genkey
./target/release/nostrfy --config nostrfy.toml restart
```

### 4-3. `restricted: unknown group` rejects group events

**Cause**: The group does not exist. In NIP-29, moderation events and join requests (9021) cannot target a group before it is created (kind 9007).

**Fix**: Create the group with a 9007 event first.

### 4-4. `restricted: you are not an admin of this group`

**Cause**: Moderation (adding members, etc.) requires an admin (a member with a role). The creator is an admin.

**Fix**: Ask an admin to grant you a role, or create your own group.

### 4-5. `restricted: this group is closed`

**Cause**: The group is `closed`; join requests without an invite code are not auto-approved.

**Fix**: Ask an admin for an invite code (9009) and join with a `code` tag.

### 4-6. Accidentally left a group, or the group has no admins

**Cause**: NIP-29 leave requests (kind 9022) are honored for any member — including the group's last admin, who leaves no admins behind. With no admin, nobody can send moderation events (9000/9001/9002/9008) anymore.

**Fix**: Sign a moderation event with the relay's own key (`relay.private_key`, the pubkey advertised as NIP-11 `self`). Per NIP-29, moderation events may come from "the relay master key or ... group admins", so the relay accepts group moderation signed by its own key even when the group has no admins. For example, restore an admin with a `kind:9000`:

```json
{
  "kind": 9000,
  "pubkey": "<relay self pubkey>",
  "tags": [["h", "<group-id>"], ["p", "<member-hex>", "admin"]]
}
```

Sign and publish it with the relay key (e.g. via `nak`, `nostrfy`'s private key, or any client configured with that key). Alternatively, delete the group with a relay-signed `kind:9008` (its stored events are purged) and re-create it with `kind:9007`. This recovery needs `relay.private_key` to be configured: if it is empty, the relay has no master key and cannot sign moderation events.

### 4-7. Protected events are rejected with `auth-required`

**Cause**: NIP-70 protected events (with a `-` tag) may only be published by the authenticated author **on the same connection**.

**Fix**: Enable NIP-42 auth in the client before publishing.

### 4-8. AUTH (NIP-42) returns `false`

Common causes:

1. `relay.public_url` is unset or wrong — the AUTH event's `relay` tag does not match the relay's URL. Set `wss://...` and `restart`
2. Stale challenge — you sent AUTH on a different connection, or reused an old challenge
3. The client clock is off — the AUTH event's `created_at` must be within ±10 minutes of now

### 4-9. NIP-86 management API returns `401 unauthorized`

**Cause**: Missing or wrong credentials.

**Fix**:

- Set `management_token` and send `Authorization: Bearer <token>`
- Or set `admin_pubkey` and send a NIP-98 auth event (the `u` tag must match the relay URL exactly; a `payload` tag is required)
- If neither is set, the management API is disabled entirely

---


### 4-10. NIP-98 auth events are rejected for a different scheme or port

The NIP-98 spec says the `u` tag must be *exactly* the same as the absolute request URL, so nostrfy derives the expected URL from `relay.public_url`: its authority plus the HTTP scheme mapped from the WebSocket scheme (`wss://` -> `https://`, `ws://` -> `http://`, `nostr+` stripped). Without `public_url` the relay expects the plain `http://host:port` it serves. A tag with another scheme, a different/omitted port, or a different path or query is rejected — set `relay.public_url` to the public address clients sign. Each auth event is also **single-use**: replaying the same `Authorization` header within its 60-second validity window is refused.

---

## 5. Database and Disk

### 5-1. `database map is full: increase database.max_map_size`

**Cause**: The LMDB memory-map ceiling (default 1 TB of virtual address space; actual disk usage grows with data) was reached — effectively, the database is full.

**Fix**: Raise `database.max_map_size` and `restart`.

### 5-2. `disk is full: refusing to commit N events`

**Cause**: Less than 32 MB of free disk space. Writes stop (to protect the data); reads continue.

**Fix**: Free up disk space. Writes resume automatically once space is available.

```bash
df -h /path/to/data
```

### 5-3. `nostrfy check` reports `map_size must not exceed max_map_size`

**Cause**: `database.map_size` is larger than `max_map_size`.

**Fix**: Set `map_size` at or below `max_map_size` (the defaults are fine).

### 5-4. Checking the database size

```bash
curl http://127.0.0.1:8080/relay/stats
# => "db_size_bytes" in bytes
```

### 5-5. Backing up / moving the database

All data lives in the `database.path` directory. **Stop the relay before copying** (copying a live database can corrupt it).

```bash
./target/release/nostrfy --config nostrfy.toml stop
cp -a ./data ./data-backup
./target/release/nostrfy --config nostrfy.toml start
```

---

## 6. Daemon Operation

### 6-1. `nostrfy stats` says `nostrfy is not running (no stats file)`

**Cause**: The stats file does not exist — the daemon is not running, or it started less than a few seconds ago.

**Fix**: Run `nostrfy start`, wait a few seconds, and try again.

### 6-2. The log grows without bound

**Cause**: `max_log_size_bytes` is 0 (rotation disabled).

**Fix**: Set `max_log_size_bytes = 52428800` (50 MB) and `max_log_files = 5`. Rotation is automatic.

### 6-3. Changes to the config do not take effect after reload

**Cause**: You reloaded (SIGHUP) settings that are fixed at startup: `private_key`, `api_host`, `metrics_enabled`, LiveKit settings, and the NIP enable/disable lists.

**Fix**: Use `nostrfy restart`. The log contains a "a restart is required" warning in this case.

### 6-4. The relay keeps dying by itself

**Cause**: The machine rebooted, or the relay ran out of memory (OOM).

**Fix**:

1. Check the end of the log: `tail -50 nostrfy.log`
2. Check if the machine rebooted: `uptime` (a very short uptime means a reboot)
3. Check memory: `free -h`
4. Start the relay again: `nostrfy start`

> **Tip**: To start nostrfy automatically on boot, register it as a systemd service with the relay's start command as `ExecStart`.

### 6-5. systemd cannot start the relay on port 80

A systemd service running as root can bind port 80. If you set `User=` to a regular user, either use a higher port (e.g. 8080) or add `AmbientCapabilities=CAP_NET_BIND_SERVICE` to the unit.

---

## 7. Still Not Solved?

1. **Check the log**: `tail -100 nostrfy.log` — it usually names the direct cause
2. **Re-validate the config**: `nostrfy check` — shows warnings and errors
3. **Gather reproduction details**: what were you doing, which client, what exact error
4. **Ask in the project repository**: https://github.com/iqbqioza/nostrfy (when filing an issue, include the reproduction steps and the log)

---

This documentation is maintained against the actual behavior of the relay. If you find an error, please consider submitting a fix.