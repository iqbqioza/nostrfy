# Migrating from strfry to nostrfy

This is the step-by-step operator guide for moving a [strfry](https://github.com/hoytech/strfry)
relay's events into nostrfy. It uses `nostrfy migrate-strfry`, which reads
strfry's own export format (JSONL, one NIP-01 event per line) and imports it
directly into the nostrfy database.

If you only want the command reference, see
[MANUAL.md §16](MANUAL.md#16-migrating-from-strfry). This document is the
complete runbook: preparation, dry run, migration, verification, cut-over,
rollback and troubleshooting.

> The migration is offline: it writes directly to `database.path` and refuses
> to run while a relay instance holds the database directory. It never writes
> to the strfry database.

---

## 1. At a glance

| Migrated | Not migrated |
| --- | --- |
| Every stored event (replaceable/addressable semantics applied) | strfry settings with no nostrfy equivalent (the merge report lists each with a reason) |
| NIP-40 expiry: already-expired events are skipped | Blossom media and its owner mappings (strfry has no Blossom server) |
| NIP-09 deletions, including the re-publication blocks for events strfry had already deleted physically | Access lists (NIP-86 bans, relay pubkey lists, Blossom allowlist) |
| NIP-29 `9005`/`9008` moderation side effects (deletions, group purge) | LiveKit settings and rooms |
| First-seen timestamps (when the new-pubkey gate is configured) | NIP-62 vanish requests (opt-in, see `--apply-vanish`) |
| NIP-29 groups, NIP-43 roles and their relay-signed metadata (`39000`/`39001`/`39002`/`39005`, `13534`), rebuilt and republished on the first start | The relay's own identity/keys (they live in `nostrfy.toml`) |
| The equivalent strfry settings, offered for merge into `nostrfy.toml` (optional) | |

Expected skips in the summary: **ephemeral events** (kinds `20000`-`29999`,
which nostrfy never stores) and **already-expired events**.

---

## 2. Requirements

- The `strfry` binary (for `--strfry-db`), or a JSONL file you exported
  yourself.
- A nostrfy build with the `migrate-strfry` subcommand (check with
  `nostrfy migrate-strfry --help`; the feature landed after v0.1.15).
- The nostrfy config (`nostrfy.toml`) for the target relay.
- Free disk space: roughly the size of the strfry export plus its indexes.
  The NIP-50 word index (`database.search_index = true`, the default) adds
  some more; on a very tight disk you can disable it, migrate, and re-enable
  it later (the index is rebuilt at startup).
- No running nostrfy instance on the target `database.path`.

---

## 3. Step 1 — Stop the nostrfy relay

```sh
nostrfy --config /etc/nostrfy/nostrfy.toml stop
```

The migration refuses to start while a daemon holds the database directory
(`cannot lock the database directory ...; stop the relay before migrating`),
so this is a hard requirement.

**strfry itself may keep running.** `strfry export` reads a consistent LMDB
snapshot, so a live strfry is fine. Events that arrive *after* the export
started are not included; if you keep strfry live, plan a catch-up run (see
§8 Resuming and catch-up).

## 4. Step 2 — Back up

```sh
# The strfry database (never modified by the migration, but keep a copy
# until you are satisfied).
sudo cp -a /var/lib/strfry-db /var/lib/strfry-db.backup-$(date +%F)

# The nostrfy config and (if it already has data) the nostrfy database.
sudo cp -a /etc/nostrfy/nostrfy.toml /etc/nostrfy/nostrfy.toml.bak
```

If the target nostrfy database already has events, the migration merges into
it (duplicates are skipped and replaceable events keep the newest version).
For a clean cut-over, migrate into a fresh, empty `database.path` instead.

## 5. Step 3 — Prepare and validate the nostrfy config

Create `nostrfy.toml` for the new relay. The important parts for a migration:

```toml
[relay]
name = "My Relay"
public_url = "wss://relay.example.com"   # needed for NIP-42/62/98 and NIP-29 metadata
private_key = "..."                       # needed for NIP-29/43 relay-signed metadata

[server]
host = "0.0.0.0"
port = 8080

[database]
path = "/var/lib/nostrfy"
map_size = 1073741824
```

Generate the relay key with `nostrfy --config ... genkey` if you do not have
one. Then validate:

```sh
nostrfy --config /etc/nostrfy/nostrfy.toml check
```

`check` also probes the port and the database directory, so fix anything it
reports before continuing.

### Merging the strfry settings (optional)

Before the database is opened, `migrate-strfry` looks for strfry's config
(`--strfry-config <PATH>`, else `$STRFRY_CONFIG`, `/etc/strfry.conf`,
`./strfry.conf`), prints the settings that have a nostrfy equivalent and
differ from your `nostrfy.toml`, and asks whether to merge them:

```
strfry settings from /etc/strfry.conf:
  relay.info.name                 -> relay.name                  My Relay -> strfry
  relay.bind                      -> server.host                 0.0.0.0 -> 127.0.0.1
  relay.port                      -> server.port                 8080 -> 7777
  ...
  note: strfry may still be listening on that port; stop it before starting nostrfy
not merged (no nostrfy equivalent):
  relay.writePolicy.plugin        nostrfy has no write-policy plugin interface
  ...
Merge these 12 setting(s) into /etc/nostrfy/nostrfy.toml? [y/N]
```

Only the listed keys are rewritten; comments and every other line are kept.
A single unusable value (for example an npub `relay.info.pubkey`, which
nostrfy cannot use) is skipped with its reason while the rest still merge,
and the file is never left invalid.

- `y` applies the merge and the migration continues with the merged config
  (so a merged `database.max_map_size` applies to this very migration).
- `--merge-config` applies without asking (for scripts).
- `--no-merge-config` skips the step entirely.
- With no terminal (e.g. `strfry export | nostrfy migrate-strfry` in CI) the
  proposals are printed and the merge is skipped unless `--merge-config` is
  given.
- `--dry-run` prints the proposals but never writes.
- An explicitly named config (`--strfry-config` or `$STRFRY_CONFIG`) that
  cannot be read is an error; an auto-discovered one is skipped with a note.
- The prompt waits for an answer (Ctrl-C aborts); in scripts use
  `--merge-config` so nothing blocks.

## 6. Step 4 — Dry run

Always look before you leap. A dry run parses and verifies the whole export
without writing anything (it does not even need the database):

```sh
# Option A: let nostrfy run `strfry export` (strfry must be on PATH)
nostrfy --config /etc/nostrfy/nostrfy.toml migrate-strfry \
    --strfry-db /var/lib/strfry-db --dry-run

# Option B: export yourself first
strfry export > /tmp/strfry-export.jsonl
nostrfy --config /etc/nostrfy/nostrfy.toml migrate-strfry \
    --input /tmp/strfry-export.jsonl --dry-run
```

Read the summary:

```
read 4806 event line(s)
valid 4806 event(s) (dry run: nothing was written)
skipped 0 event(s): 0 malformed, 0 oversized, 0 bad signature, ...
```

A non-zero `bad signature` count means the export contains events strfry
accepted without verification (e.g. imported with `--no-verify`); they will
be skipped. If you trust them, pass `--no-verify` to import them anyway.

The dry run classifies ephemeral and already-expired events (they are never
stored) but does not simulate the NIP-09/NIP-29 deletion side effects, which
need the database: expect the real run's side-effect counts to be non-zero.

## 7. Step 5 — Migrate

Pick one of the three input modes. All of them produce the same result.

```sh
# Option A — nostrfy runs the export (strfry on PATH, or --strfry-bin /path)
nostrfy --config /etc/nostrfy/nostrfy.toml migrate-strfry \
    --strfry-db /var/lib/strfry-db

# Option B — you exported to a file
nostrfy --config /etc/nostrfy/nostrfy.toml migrate-strfry \
    --input /tmp/strfry-export.jsonl

# Option C — pipe (stdin is the default input)
strfry export | nostrfy --config /etc/nostrfy/nostrfy.toml migrate-strfry
```

Useful flags:

| Flag | Why |
| --- | --- |
| `--strfry-bin <PATH>` | strfry is not on `PATH` |
| `--since <UNIX>` | resume/catch-up: export only events with this `created_at` or newer (inclusive) |
| `--apply-vanish` | honor NIP-62 vanish requests found in the export (off by default) |
| `--no-verify` | skip signature verification for trusted dumps (faster) |
| `--batch <N>` | events per database transaction (default 512) |
| `--dry-run` | parse/verify only |

With `--strfry-db`, strfry's own log lines (its banner and `CONFIG: ...`
messages) appear around nostrfy's output; they are harmless, and strfry
errors stay visible there.

The migration is safe to re-run: duplicates are skipped and the deletion
side effects are re-applied, so an interrupted run can simply be repeated
(or resumed with `--since <last created_at>`).

## 8. Step 6 — Start and verify

```sh
nostrfy --config /etc/nostrfy/nostrfy.toml start
```

The first start rebuilds the NIP-29 group store and the NIP-43 role store
from the imported events and republishes the relay-signed metadata
(`39000`/`39001`/`39002`/`39005` per group, the `13534` membership list).
On a large database this can take a moment; watch the log:

```sh
tail -f /var/log/nostrfy.log
```

Then verify (replace the URLs and pubkeys):

```sh
R=wss://relay.example.com      # for nak (WebSocket)
H=https://relay.example.com    # for curl (HTTP)

# 1. The relay answers and advertises its NIPs.
nak relay "$R"

# 2. The relay serves events (sanity check; paginate for exact totals).
curl -s "$H/api/v1/query?limit=1" | head -c 200

# 3. A previously deleted event is gone and stays gone: re-publishing the
#    exact same event must fail.
nak req -i <deleted-event-id> "$R"

# 4. NIP-29 group metadata (if you migrated groups).
nak req -k 39000 "$R"
nak req -k 39001 "$R"
nak req -k 39002 "$R"

# 5. NIP-43 membership list (protected; needs NIP-42 AUTH).
nak req --auth --force-pre-auth --sec <nsec> -k 13534 "$R"

# 6. Private groups: anonymous must NOT see their posts; a member must.
nak req -k 9 -h <group-id> "$R"
nak req --auth --force-pre-auth --sec <member-nsec> -k 9 -h <group-id> "$R"
```

For an exact event-count comparison, `strfry scan '{}' | wc -l` minus the
ephemeral/expired events reported by the migration summary should equal what
clients can retrieve (paginate with `until` on large databases).

## 9. Step 7 — Cut over

1. Point your reverse proxy / DNS at the nostrfy instance (TLS, WebSocket
   upgrade; see the deployment guides in `docs/deploy/`).
2. Update your clients' relay lists (NIP-65) or the relay URL in your apps.
3. Keep the strfry database and its backup for a while. If strfry was live
   during the export, do a catch-up run once you are ready to switch:
   stop nostrfy, then re-run the migration with `--since <last created_at>`
   from the previous summary (inclusive; duplicates are skipped), start
   nostrfy again.

---

## 10. Resuming an interrupted migration

An interrupted run leaves a consistent database: every committed batch is
durable and re-running is safe.

> **Do not start the relay before re-running.** The NIP-29 group side
> effects (`9005`/`9008`) are applied after the import; an interrupted run
> has stored those events but not their deletions yet, so the first start
> could serve group history the deletion was meant to remove. Re-run the
> migration first: it completes the side effects (the purge is idempotent)
> and only then start the relay.

- **You exported to a file / piped**: re-run the same command. Duplicates are
  skipped, and the deletion blocks are re-applied.
- **You used `--strfry-db`**: the summary prints a resume hint like
  `resume hint: re-run with --strfry-db and --since 1789990160 ...`. Re-run
  with that `--since` (inclusive, so the boundary second is re-imported and
  deduplicated).
- If the run failed with `database writer unavailable`, check free disk
  space and `database.map_size`, then re-run.

## 11. Rollback

The migration only writes to the nostrfy database. To roll back:

```sh
nostrfy --config /etc/nostrfy/nostrfy.toml stop
rm -rf /var/lib/nostrfy            # or restore the pre-migration backup
# start strfry again, or migrate into a fresh database
```

## 12. Troubleshooting

| Message | Cause / fix |
| --- | --- |
| `cannot lock the database directory ...; stop the relay before migrating` | A nostrfy daemon (or another migration) holds the directory: `nostrfy stop` first |
| `strfry database directory ... does not exist` | `--strfry-db` must name the directory that contains `data.mdb` |
| `cannot run 'strfry': ...` | Install strfry, set `--strfry-bin`, or use `--input` |
| `strfry export exited with exit status N` | strfry refused to export (wrong `db` path, incompatible DB): run `strfry --config <conf> export` manually to see the error |
| `database writer unavailable; the migration did not complete` | The writer thread stopped or the queue is overloaded: check disk/map size, re-run (safe) |
| `group purge for <id> did not complete` | The purge was interrupted: re-run the migration |
| High `bad signature` count | The strfry DB contains unverified events: inspect them; import with `--no-verify` only if you trust the source |
| High `expired`/`ephemeral` counts | Expected: nostrfy never stores ephemeral events, and expired events are dropped |
| First start is slow | The group/role state is being rebuilt from the imported events; it is a one-time cost, logged in the log file |
| `database writer unavailable` while the disk or LMDB map is full | Raise `database.map_size` (and `max_map_size`), free disk space, then re-run (safe) |
| NIP-29 metadata missing after the start | The relay has no `relay.private_key`, so it cannot sign `39000`/`39001`/`39002`/`39005`: run `nostrfy genkey` and restart |
| The settings merge is not offered | strfry's config was not found: pass `--strfry-config /etc/strfry.conf` (or set `$STRFRY_CONFIG`) |

## 13. Checklist

```text
[ ] nostrfy relay stopped
[ ] strfry DB backed up; nostrfy config backed up
[ ] nostrfy.toml has database.path, public_url and private_key
[ ] `nostrfy check` passes
[ ] strfry settings merged (or the report reviewed and dismissed)
[ ] dry run reviewed (no unexpected bad signatures)
[ ] migration completed without errors
[ ] relay starts; group/role rebuild logged
[ ] event counts match (minus ephemeral/expired)
[ ] deleted events stay gone (re-publish rejected)
[ ] group metadata (39000/39001/39002/39005) and 13534 present
[ ] private-group visibility checked anonymously and as a member
[ ] reverse proxy / DNS / client relay lists updated
[ ] strfry backup retained until the cut-over is confirmed
```
