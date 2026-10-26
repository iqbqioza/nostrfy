# Using the Buzz desktop app with nostrfy

[Buzz](https://buzz.xyz) is a Nostr client built around NIP-29 relay groups.
It uses the WebSocket relay for live traffic and a NIP-98-authenticated HTTP
bridge for its read models and writes. nostrfy implements that bridge and the
channel extensions Buzz relies on, so a stock Buzz desktop app can add a
nostrfy relay as a community.

## Requirements

- Enable the compatibility layer: set `relay.enabled_buzz = true` (default
  `false`). Without it the `/info`, `/query`, `/events` and `/count` bridge
  routes are not served, so a stock Buzz client cannot use the relay.
  `enabled_buzz` is read at startup; changing it requires a restart.

With `enabled_buzz = false` the relay keeps the pre-Buzz NIP-29 behavior:
`9002` replaces the whole group metadata (Buzz mode makes it a partial
update), `39002` carries bare `p` tags, the creator is the `admin` role,
plain `9007` tags are not treated as initial metadata (use `9002`), and
NIP-CL channel tags/guests/bots are ignored. The exception is a group with
Buzz provenance (a non-empty `channel_type` or a stored Buzz partial edit):
it keeps the partial-edit privacy floor in live plain mode and replay, so
a mode switch cannot expose its private messages. This keeps ordinary
NIP-29 clients unaffected by the compatibility layer.
- A relay signing key: set `relay.private_key` (64 hex chars, generated with
  `nostrfy genkey`). Buzz needs the relay's `kind:39000` metadata, system
  messages and membership notices, all signed by this key.
- A public URL that matches the URL clients use:
  `relay.public_url = "wss://relay.example.com"`. NIP-98 and NIP-42 compare
  the exact URL, so a mismatch fails auth.
- Media uploads (avatars, attachments): a Blossom backend. Set
  `[blossom]` `host`, `storage` and either `local_path` or the S3 keys. Buzz
  uploads to the relay origin and nostrfy serves the same store at
  `/media/...` as well as on the dedicated media host.

## Adding the community in Buzz

1. In Buzz, choose **Add community → Join an existing community**.
2. Enter the relay's `wss://` URL (or its `https://` URL; Buzz normalizes it).
3. Buzz probes `GET /info` and, when NIP-43 is advertised, checks that your
   pubkey is on the relay's membership list.

An **open** nostrfy relay does not advertise NIP-43, so Buzz treats it as an
open community and lets any identity join. A **closed** relay
(`access.restrict_relay = true`, i.e. the allowlist is enforced) advertises
NIP-43 and includes the allowlisted pubkeys in its `kind:13534` membership
list. Use `advertise_nip43 = true` only for a role-managed relay that wants
Buzz to gate onboarding without an allowlist.

The `kind:13534` membership list always gives the `owner` role to the
relay's NIP-11 `pubkey` (`relay.pubkey`) and to `rpc.admin_pubkey`, so
Buzz's community-members panel shows the operator as the owner instead of
an absent or plain member. The relay's signing key (`relay.private_key`,
NIP-11 `self`) is not added: it is the event signer, not an administrator
identity.

## HTTP bridge

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /info` | none | NIP-11 relay information document |
| `POST /query` | NIP-98 | One-shot filters; returns a flat JSON array of events |
| `POST /events` | NIP-98 | Publish one signed event |
| `POST /count` | NIP-98 | NIP-45-style count for the supplied filters |

`POST /query`, `/events` and `/count` require the NIP-98 `payload` tag with
the SHA-256 of the exact request body, and every authorization is single-use
(the shared replay guard).

Bridge filters accept Buzz's extension fields in addition to NIP-01:

- `until` + `before_id` — the composite `(created_at, event_id)` cursor used
  by `get_channel_messages_before`; `before_id` without `until` is rejected.
- `top_level`, `include_aux`, `include_summaries` — NIP-CW channel windows.
  A served window returns the rows, the aux closure, relay-signed `kind:39005`
  thread summaries, and exactly one relay-signed `kind:39006` bounds event.
- `depth_limit` (+ optional `thread_cursor` / `thread_cursor_id`) — the legacy
  thread-subtree path used by the thread panel.

`/query` applies the same visibility rules as an authenticated WebSocket
connection: NIP-70 protected events, NIP-59 gift-wrap recipients, NIP-78
owner-only state, NIP-29 private/hidden groups, and per-pubkey state
(`kind:44100`/`44101` membership notices and `kind:30622` DM visibility
snapshots).

## NIP-29 channel metadata

Buzz and NIP-CL use tags that plain NIP-29 does not define. nostrfy accepts
and publishes them:

- `kind:9007` / `9002`: `visibility` (`open`/`private`), `channel_type`
  (`stream`, `forum`, `dm`, `workflow`, `system`), `t` labels, `ttl`, `topic`,
  `purpose`, `archived` and `join_role`.
- `kind:39000` also carries `t` (type, then labels), `P` (creator) and
  `created_at`; `39001`/`39002` carry the same identity tags. `39003` lists
  the `guest` and `bot` tiers alongside the ordinary roles, matching the
  role column in `39002`.
- `visibility=private` implies member-only writes (Buzz's channel model). A
  DM or system channel is private and its metadata is hidden unless the
  create event says `visibility=open`.
- Metadata edits are **partial**: a `9002` without a tag leaves that setting
  unchanged; `["visibility","open"]`/`["visibility","private"]` set the
  visibility, an empty optional text/`join_role` value clears that field,
  and `["ttl",""]` clears the TTL. A subgroup is detached with an explicit
  empty `["parent",""]`; omitting `parent` keeps the existing link. This
  follows NIP-CL/Buzz; plain NIP-29 clients that send every field still
  work.

## Relay-signed Buzz events

- `kind:40099` — channel timeline system messages (`channel_created`,
  `member_joined`, `member_left`, `member_removed`).
- `kind:44100` / `44101` — membership notices with `p` (target), `h`
  (channel) and `t` (channel type). Stored globally, read-gated by `p`.
- `kind:30622` — NIP-DV per-viewer hidden-DM snapshot, published by
  `kind:41012` (hide) and a re-open `kind:41010`.
- `kind:41010` / `41012` — Buzz DM open/hide commands. The relay derives a
  deterministic DM channel id from the sorted participant pubkeys, creates a
  private/hidden NIP-29 group, and answers the open command with
  `response:{"channel_id":"..."}` in the OK message.

Client submissions of the relay-signed kinds above (`40099`, `44100`/
`44101`, `30622`, the query-time `39005`/`39006` overlays, and the NIP-IA
`13535` snapshot) are rejected. `41010`/`41012` are client commands: they
are accepted, applied to the derived group state, and never stored as
ordinary events.

## Media

Image attachments are accepted only when the relay has a Blossom server
(`[blossom] host` and storage): a message carrying a NIP-92 `imeta` tag with
an `image/…` MIME is rejected with `blocked: image attachments require a
configured Blossom server` when Blossom is disabled. Profile pictures and
other external image URLs are not `imeta` attachments and stay accepted.

When Blossom is configured, the relay origin serves:

- `PUT /media/upload` (and the standard `PUT /upload` on the media host)
- `GET /media/{sha256}.{ext}` and `HEAD`

The BUD-11 `server` tag may name either the Blossom host or the relay's public
host, because Buzz signs the relay URL it uploads to.

## Known gaps

- NIP-IA archive/unarchive requests (`kind:9035`/`9036`) are not accepted
  yet. The relay does publish the required empty `kind:13535` archived-
  identities snapshot on startup, so Buzz's archive-state check completes
  with "nothing archived" instead of failing.
- Channel `ttl` is published but stored messages are not automatically
  expired server-side; clients that set NIP-40 `expiration` get normal expiry.
- NIP-CL's system-channel exclusion is applied to the HTTP bridge; a global
  WebSocket subscription can still receive a system channel's relay-signed
  state unless it names the channel.
- Buzz's relay-member management commands (`kind:9030`-`9032`) are not wired
  to nostrfy's access lists; manage an allowlist relay with `nostrfy relay
  allow/deny` or NIP-86 instead. Channel member management (`kind:9000`/
  `9001`) and the member UI do work.
- Buzz's workspace-profile command (`kind:9033`) is stored as an ordinary
  event but does not update the NIP-11 `icon`; set `relay.icon` in the
  configuration instead.
- A `kind:39005` summary's `reply_count` counts direct replies and
  `descendant_count` currently carries the same value; fully nested reply
  trees are not walked when synthesising the overlay.
- The legacy `depth_limit` thread path returns the subtree without a
  `kind:39007` thread-bounds overlay; only the channel-window path emits its
  `kind:39006` bounds event.
- DM groups are derived state backed by the group snapshot: the synthetic
  `9007`/`9000` are not stored, so a snapshot-less full rebuild (new
  database, migration, or dropped snapshot) cannot recreate a DM channel.
  Runtime state-removal rebuilds carry live DM groups across the swap.
  Hidden-DM sets are snapshot-backed for the same reason.
- Enabling `enabled_buzz` on an existing relay upgrades the creator role in
  the restored snapshot (and disabling it maps a Buzz-created channel's
  restored `owner` default back to `admin`), but the mode switch itself does
  not rewrite the stored `39001`/`39002`; the next metadata or membership
  change does. A snapshot restart schedules one roster refresh for groups
  above the 1,000-member throttle threshold, but not for `39001` or smaller
  groups.
- The `owner` entries in `13534` are roster metadata, not an access-list
  bypass. `relay.pubkey` has the operator publishing exemption;
  `rpc.admin_pubkey` does not, so on a `restrict_relay` relay add it to the
  allowlist if it should publish too. NIP-86 `banpubkey` removes an
  allowlist entry but does not automatically remove NIP-43 role
  assignments.
- DM channel ids are derived from `relay.private_key`. Rotating the relay
  key changes every derived id: old DM groups remain in the snapshot, while
  a new open creates a new channel. There is no automatic DM migration.
- In Buzz mode, a restored creator whose only role is exactly `admin` is
  upgraded to `owner`. An explicit later demotion from owner to `admin`
  uses the same exact shape and is therefore indistinguishable from the old
  default on the next snapshot restore; use a non-default role label when a
  deliberate demotion must survive a restart.
- Re-opening an existing DM whose participant set is incomplete (for example
  after an admin removed a member) is rejected rather than acknowledged as a
  partial channel. The existing channel is left intact; an admin can
  re-admit the member with `kind:9000`.
- If Buzz is disabled and the group state has to be rebuilt from events,
  the create's privacy floor is kept and a Buzz-created channel that carries
  a `channel_type`/`visibility` marker keeps its channel type and metadata.
  Guest/bot tiers and separate `role` tag grants are replayed with plain
  NIP-29 semantics and may be lost; the normal snapshot restore keeps them.
  A plain-mode full `9002` that detaches a subgroup by omitting `parent` is
  replayed as a Buzz partial edit; use an explicit empty `["parent",""]` on
  a Buzz-origin channel if the detach must survive a mode-off rebuild.
- The `buzz_metadata` provenance of a plain-origin group edited while Buzz
  was enabled is snapshot-backed. A snapshot-less rebuild can infer Buzz
  origin from `channel_type`/`visibility`, but not from a Buzz edit that
  carried only ordinary fields (for example a name-only rename); such a
  group falls back to plain whole-metadata replay and may lose its privacy
  floor. Keep the snapshot if this transition matters.
- A stored `9002` that turns LiveKit off is replayed with `emit=false`, so
  its empty `kind:39004` is not republished by a snapshot-less rebuild. The
  old participant list can remain until the room is reconfigured; the
  LiveKit poll skips the now-inactive group.
- The rebuild's same-second tie-break cannot recover arrival order between
  a `9001` remove and a `9000` re-add, or a `9022` leave and a `9021`
  rejoin. The remove/leave wins on replay until the next edit; store an
  explicit later role/join event if that state must survive a restart.
- Enabling Buzz on a restored plain-NIP-29 group does not reinterpret
  literal `guest`/`bot` role labels. Such a role was an ordinary privileged
  role in plain mode, while Buzz reports it as a read-only/bot tier. Use a
  non-reserved label if the group will switch modes, or promote/reassign
  the member after enabling Buzz.
- A vanish that removes no group-state event only drops memberships from
  the live store and snapshot. If NIP-29 is disabled at that moment, the
  in-memory removal is skipped; a later re-enable can restore the member
  from the pre-vanish snapshot until a state rebuild applies the vanish
  filter.
- The migration cannot distinguish a JOIN admitted with a `9009` invite
  that was later deleted from a forged code-bearing JOIN to a closed group.
  It keeps a code-bearing JOIN (and drops a code-less JOIN to a group that
  is closed at that point in the chronological replay) so a legitimate
  member is not lost when the invite was revoked after the join.
- The bridge inherits the relay's filter bounds: a single filter with more
  than 512 ids/authors/kinds/tag values is rejected, and the over-fetch
  window is capped at 2,000 events. Window/thread requests also cap their
  combined output at 20,000 events. A community with more than 512 channels
  may need to split its channel-list query.
- Channel-window pagination can stall if one `created_at` second contains
  more candidates than the bounded fetch. The legacy `depth_limit` thread
  path also scans only the newest 1,000 direct replies per frontier, so
  older replies behind that prefix are not returned. Split the timestamp
  window (or use the channel-window path) for unusually dense bursts.
- Aggregate `approximate` flags come from the raw database scan, before
  visibility filtering. A filter dominated by hidden rows can therefore
  report `approximate=true` with a small visible count; the count itself
  never includes hidden rows.
- NIP-29 and NIP-43 snapshots share one removal stamp. A group-state
  removal or purge can invalidate the role snapshot, forcing a role rebuild
  and dropping snapshot-only invite codes; role removals likewise invalidate
  the group snapshot. The events remain the source of truth.
- NIP-77 negentropy sync returns ids/timestamps without applying the
  per-pubkey gate to `44100`/`44101`/`30622`; an anonymous syncer can learn
  that those events exist, while REQ/COUNT still withhold their content.
  This is the pre-existing NEG visibility limitation, not a content leak.
- Buzz's push leases, workflow commands, moderation commands and
  hosted-community APIs are not part of this bridge.
- NIP-34 git events (used by Buzz Projects) are rejected unless
  `relay.enabled_git = true`.
