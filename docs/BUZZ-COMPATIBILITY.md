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
NIP-CL channel tags/guests/bots are not applied. A plain group rejects
`channel_type`/`visibility` tags on create/edit instead of ignoring them,
because the rebuild would otherwise honor a stored tag the live path
ignored. The exception is a group with Buzz provenance (a non-empty
`channel_type` or a stored Buzz partial edit): it keeps the partial-edit
privacy floor in live plain mode and replay, so a mode switch cannot expose
its private messages. Apart from that floor, a live plain `9002` still
replaces ordinary NIP-29 metadata. This keeps ordinary NIP-29 clients
unaffected by the compatibility layer.
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
- `thread_window: true` + `#e` root + `kinds` — NIP-CW thread mode. Returns
  the newest-first descendant page and exactly one request-bound
  relay-signed `kind:39007` bounds event.

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
`44101`, `30622`, the query-time `39005`/`39006`/`39007` overlays, and the
NIP-IA `13535` snapshot) are rejected. `41010`/`41012` are client commands: they
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

- NIP-IA archive/unarchive requests (`kind:9035`/`9036`) are accepted from a
  self-request, a relay owner/admin, or either NIP-OA owner-of-agent path
  (request-borne `auth` or the target's latest kind:0 profile attestation),
  with NIP-70/freshness/tag validation. Accepted state changes emit
  `kind:8002`/`8003` deltas and a fresh relay-signed `kind:13535` snapshot,
  persisted in an additive `index_meta` key. Profile-attestation archives
  include the marked `proof` e-tag on the delta. Archive state is visibility
  metadata only: history is not deleted and `13534` membership is not
  rewritten.
- Channel `ttl` is enforced at read time for non-state channel content on
  WebSocket REQ/COUNT/live/NEG, the HTTP bridge and the REST API. Messages
  older than the group's TTL are hidden immediately, including after a TTL
  edit. Startup and the periodic database-maintenance tick perform a bounded
  physical purge for TTL groups; the ascending scan advances past full pages
  that contain only group state/metadata, so older expired content is still
  reclaimed. Read-time enforcement remains authoritative if a maintenance
  scan is interrupted. NIP-40 `expiration` remains independent.
- NIP-CL's system-channel exclusion is applied to the HTTP bridge and to
  WebSocket REQ, COUNT, live delivery and NEG: a global filter does not
  receive a system channel's relay-signed state unless it names the channel
  (`#h`, `#d`, `#t:system` or `#P`).
- Buzz's relay-member management commands (`kind:9030`-`9032`) are accepted
  from a relay owner/NIP-86 admin or a NIP-43 `owner`/`admin` assignment and
  update the NIP-43 role roster (member/admin; role changes use the same
  roles). They update `kind:13534` and persist the role snapshot. They do not
  edit the NIP-86 allowlist used by `restrict_relay`; manage that separately
  with `nostrfy relay allow/deny` or NIP-86. Channel member management
  (`kind:9000`/`9001`) and the member UI work as before.
- Buzz's workspace-profile command (`kind:9033`) is accepted from a relay
  owner/NIP-86 admin or a NIP-43 `owner`/`admin` assignment. It validates the
  single `icon` tag (`https://` or `data:image/`, or empty), updates the
  NIP-11 icon immediately, and persists `relay.icon` when a config path is
  available; a failed file write rolls the in-memory change back. The
  command event itself is still stored as an ordinary event.
- A `kind:39005` summary counts visible direct replies and walks the
  descendant tree (up to 100 levels / 10,000 events) for
  `descendant_count`, `last_reply_at` and the 10 most recent participants.
  Hidden intermediates are traversed without being counted themselves, and
  the NIP-10 root marker keeps visible descendants behind a deleted/missing
  parent in the count. The direct/frontier query bound matches the
  10,000-event walk cap; a tree larger than that can still undercount the
  summary.
- `thread_window:true` / `kind:39007` thread mode walks descendants to the
  requested depth, bounded at 8,192 events and 1,000 rows per frontier query.
  Its bounds binding names the request `Host` authority, so a reverse proxy
  must preserve the original `Host`. A deleted root keeps minimal tombstone
  metadata (`kind` + channel) and still serves its retained replies; a root
  with no event or tombstone returns an empty, unbounded thread. The
  thread-mode batch rechecks its channel access after building the page and
  returns a retryable `503` if access changed. The legacy `depth_limit` path
  intentionally has no signed bounds event (clients use the legacy short-page
  heuristic); it queries up to 1,000 direct replies per frontier (a complete
  same-second group can exceed that cap) and returns `413` when the DB
  reports a truncated frontier instead of silently dropping older replies.
- DM groups are derived state backed by the group snapshot: the synthetic
  `9007`/`9000` are not stored, so the event rebuild cannot recreate a DM
  channel. Every main snapshot save now also writes an additive
  `groups:dm_backup` copy of the DM groups in the same LMDB transaction.
  If the main snapshot is missing but the database generation still
  matches, startup merges those DMs after the event rebuild; a backup that
  predates a state removal/event is rejected. When that backup is also
  missing, the rebuild reconstructs a DM from the relay-signed
  `39000`/`39001`/`39002` and `30622` metadata (current relay key only),
  skipping deleted/ghosted ids and vanished participants. A truly new
  database, or a migration with no snapshot, backup, or metadata events,
  still has no DM state; the migration carry handles its own transition.
  Runtime state-removal rebuilds carry live DM groups across the swap.
  Creation and hide persist the snapshot synchronously before the ACK (a
  failed save is retryable), so a crash cannot leave a current pre-DM
  snapshot that makes the unknown channel public. Hidden-DM sets are
  snapshot-backed for the same reason.
- Enabling or disabling `enabled_buzz` on an existing relay upgrades/maps
  the creator role in the restored snapshot and records the mode in the
  group snapshot. The next startup detects a mode change (including an old
  snapshot with no recorded mode) and republishes `39000`/`39001`/`39002`
  for every group, so the rosters do not wait for the next metadata or
  membership mutation.
- A vanish that lands while a NIP-43 rebuild is in flight publishes a
  remove-user event; a clean rebuild then republishes the full `13534`
  roster even when the rebuilt store is empty and the old snapshot is
  preserved, so the current-key roster does not keep the vanished
  identity. A failed rebuild or failed roster publish still leaves the
  previous list until the next retry.
- Vanish is exempt from the publish rate limit. While a role rebuild is
  pending, each vanish force-captures a removal in the bounded replay
  buffer; a burst from fresh keys can overflow it and force another rebuild.
  The rebuild itself filters the vanished set, so this is an availability
  bound rather than a membership resurrection.
- The `owner` entries in `13534` are roster metadata, not an access-list
  bypass. `relay.pubkey` has the operator publishing exemption;
  `rpc.admin_pubkey` does not, so on a `restrict_relay` relay add it to the
  allowlist if it should publish too. NIP-86 `banpubkey` removes an
  allowlist entry but does not automatically remove NIP-43 role
  assignments.
- DM channel ids are derived from `relay.private_key`. Rotating the relay
  key changes the derived id, but a DM open now reuses an existing
  snapshot-backed DM whose participant set exactly matches, so the old
  channel and its history remain reachable. A channel with incomplete or
  extra participants is not reused; there is no general automatic DM-id
  migration.
- In Buzz mode, a restored creator whose only role is exactly `admin` is
  upgraded to `owner` only when the snapshot has no explicit creator-role
  edit marker. A `9000`/`9001` edit of the creator sets that marker in the
  snapshot, so a deliberate owner→admin demotion (or a plain-mode role
  change) survives later Buzz-mode restores. Old snapshots without the
  marker keep the previous upgrade behavior.
- Re-opening an existing DM whose participant set is incomplete (for example
  after an admin removed a member) is rejected rather than acknowledged as a
  partial channel. The existing channel is left intact; an admin can
  re-admit the member with `kind:9000`.
- If Buzz is disabled and the group state has to be rebuilt from events,
  the create's privacy floor is kept and a Buzz-created channel that carries
  a `channel_type`/`visibility` marker keeps its channel type and metadata.
  The same-transaction `groups:buzz_backup` restores the `buzz_metadata`
  provenance, guest/bot tiers and separate `role` grants for matching
  groups when its generation still matches; a new database or a migration
  without that backup replays them with plain NIP-29 semantics and may lose
  them. A plain-mode full `9002` on a Buzz-origin channel is replayed as a
  Buzz partial edit, so an omitted `parent`/`child`, `supported_kinds` or
  other field is preserved rather than cleared; use explicit empty values
  where the field supports one, or keep the snapshot. This is the replay
  counterpart of the live privacy floor.
- The `buzz_metadata` provenance of a plain-origin group edited while Buzz
  was enabled is snapshot-backed. A snapshot-less rebuild can recover the
  marker from the additive `groups:buzz_backup` when the generation still
  matches; without it, inference from `channel_type` or a
  `visibility=private` edit covers most cases, but not a Buzz edit that
  carried only ordinary fields (for example a name-only rename). Such a
  group then falls back to plain whole-metadata replay and may lose its
  privacy floor.
- Plain-mode events imported from an older database or migration may still
  carry `channel_type`/`visibility` even though new plain-mode submissions
  reject them. The history replay applies their privacy floor; the live
  path cannot undo that legacy marker.
- A stored `9002` that turns LiveKit off is replayed with `emit=false`, so
  its empty `kind:39004` is not republished by the rebuild itself. The next
  LiveKit poll clears it: the startup cache is seeded from the stored
  participant list and an empty replacement is published for a
  still-existing non-LiveKit group; a deleted group's cache entry is simply
  dropped.
- New group-state events receive a durable arrival sequence in the additive
  `arrival:` index, and the rebuild orders ordinary state operations by that
  sequence within one second. A remove followed by a rejoin therefore
  survives, and a rejoin followed by a remove stays removed. `9007`/`9008`
  retain structural precedence. New migrations assign the export order to
  imported group state; events imported before this index, and other legacy
  rows, fall back to the conservative remove-wins rule.
- A JOIN accepted with a `created_at` far in the future (up to
  `max_created_at_future_secs`) could sort after a later removal on replay
  and re-add an open-group member. Group/join/leave events reject a future
  timestamp beyond 600 seconds, and both live-state replay and migration
  replay now skip legacy group state more than 600 seconds ahead. Events
  within that 600-second skew window still follow timestamp order. The
  relay's signing mirror is stamped at apply time, so it does not amplify
  the problem.
- Live group validation rejects a state event timestamped before its
  group's create, and the rebuild buffers such legacy state until the create
  is seen. Live client moderation is bound to the group create id across
  delete/recreate, and accepted state events record that epoch in an
  additive `group_epoch:` key namespace in `index_meta`, checked during
  rebuild; relay-generated `9000`/`9001` mirrors carry the create id and are
  ignored against a later incarnation. On the first startup after upgrading,
  a one-time scan binds every currently stored group-state event to its
  group's current create id, so pre-existing and imported rows are protected
  from the *next* recreate. It cannot reconstruct a past incarnation that was
  already deleted, and an old future-dated event that already crossed a
  recreate before the upgrade remains applied. The keys are additive: an old
  database opens with no entries and keeps the timestamp/create-id fallback.
  Migration buffers pre-create state until the create, re-adjudicates it
  against the real group, and then applies it; a pre-create `9008` is kept
  but has no effect, matching the rebuild.
- Migration saves DM-only groups to an additive `index_meta` carry, then
  invalidates the main group snapshot. The first start rebuilds/ghost-checks
  all event-derived groups from the imported history and finally merges the
  DM carry into the fresh store, so DM membership survives without skipping
  verification of imported private history.
- Migration records NIP-09 deletions and NIP-62 vanish markers while
  streaming, then runs their removal walks after the 9005/9008 fixpoint. The
  NIP-62 marker still blocks later rows in the same export immediately, but
  an admin's vanish no longer erases the admin's own deferred
  `9005`/`9008` before its effect. Do not run an incremental migration over
  a live role/group database without a subsequent full rebuild.
- Enabling Buzz on a restored plain-NIP-29 group does not reinterpret
  literal `guest`/`bot` role labels. Such a role was an ordinary privileged
  role in plain mode, while Buzz reports it as a read-only/bot tier. Use a
  non-reserved label if the group will switch modes, or promote/reassign
  the member after enabling Buzz.
- A vanish that removes no group-state event drops memberships from the
  live store and persists the snapshot even while NIP-29 is disabled. If
  that snapshot persist fails, the affected groups are marked stale rather
  than leaving a pre-vanish snapshot restorable after re-enabling NIP-29.
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
- Channel-window pagination refetches a complete dense `created_at` second
  (up to 2,000 events) when the composite cursor cannot advance, so hidden
  replies in that second cannot strand an older visible row. A second above
  that cap, or a visible page that would have to split one second, returns
  `413` instead of an empty/exhausted page. An entirely hidden prefix that
  outlasts the four over-fetch rounds also returns `413` rather than an
  empty/exhausted page with no visible cursor. The legacy `depth_limit`
  thread path scans only the newest 1,000 direct replies per frontier, so
  older replies behind that prefix are not returned. Split the timestamp
  window (or use the channel-window path) for unusually dense bursts.
- Without `relay.public_url`, the bridge NIP-98 check accepts the configured
  bind host plus loopback aliases. A proxy or LAN hostname must set
  `public_url`; an arbitrary request `Host` is deliberately not trusted.
- Count/stats/daily/monthly/hourly `approximate` flags now describe
  truncation of the visible result, not hidden scan rows. The sampled
  relay-wide kind/author aggregates also set `approximate` only when the
  visible sample itself is saturated, so hidden rows cannot set it; their
  counts still come from the newest 20,000 raw events, may undercount older
  visible events, and are marked `sampled: true`.
- NIP-29 and NIP-43 snapshots share one removal stamp. A group-state
  removal or purge can invalidate the role snapshot, forcing a role rebuild
  (stale-snapshot invite codes are carried across); role removals likewise
  invalidate the group snapshot. The events remain the source of truth.
- A role rebuild is deferred while NIP-43 is disabled; the snapshot's claims
  are carried over when it is re-enabled. Synthetic owner/allowlist roster
  entries are not treated as role-bearing assignments, and a vanished
  owner/allowlist entry is filtered from newly published `13534` rosters.
  A role rebuild that is aborted or overflows retains captured mutations for
  the next scan; on shutdown the bounded mutation journal is persisted under
  an additive `index_meta` key and replayed after the next startup rebuild,
  then cleared once the role snapshot is saved. The shutdown save is retried
  a few times; if every attempt fails, the captured leaves are still only in
  memory and can be lost. A removal
  generation now blocks a full `13534` publish before it is stored and
  deletes one that raced the pre-check; a write that starts after that
  post-store check can still be transiently visible until the rebuild
  republishes the roster.
- Buzz's push leases, workflow commands, moderation commands and
  hosted-community APIs are not part of this bridge.
- NIP-34 git events (used by Buzz Projects) are rejected unless
  `relay.enabled_git = true`.
