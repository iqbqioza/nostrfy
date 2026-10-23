# Deploying nostrfy to Fly.io

This guide deploys nostrfy to [Fly.io](https://fly.io) in a few minutes. The repository ships a ready-made template:

| File | Purpose |
| --- | --- |
| `Dockerfile` | Container image — installs the pre-built release binary with `install.sh` (auto-detects x86_64/aarch64, verifies the sha256 checksum); `NOSTRFY_VERSION` build-arg pins a release |
| `fly.toml` | Fly app configuration: HTTP service on port 8080, health checks, the `/data` volume mount, always-on machines |
| `deploy/nostrfy.container.toml` | The relay configuration baked into the image at `/etc/nostrfy/nostrfy.toml` |

## Prerequisites

- A [Fly.io](https://fly.io) account
- The [flyctl CLI](https://fly.io/docs/flyctl/) (`fly version`)
- Logged in: `fly auth login`

## Deploy in 4 steps

### 1. Launch the app (without deploying yet)

```sh
cd /path/to/nostrfy
fly launch --no-deploy --name <your-app-name> --region <region>
```

- `<your-app-name>` must be unique on Fly (it becomes part of the relay URL: `wss://<your-app-name>.fly.dev`)
- `<region>`: e.g. `nrt` (Tokyo), `fra`, `iad`, `sjc` — pick the region closest to your users
- This may overwrite the template's `fly.toml` values (app name, region) — that is fine

### 2. Create the persistent volume

The LMDB database lives on a Fly volume mounted at `/data`:

```sh
fly volumes create data --size 1 --region <region>
```

1 GB is enough to start (the database grows with usage). You can resize later, or create a larger volume from the start.

### 3. Configure the relay

Edit `deploy/nostrfy.container.toml` before deploying. **Never put the relay key in this file**: it is baked into the image layer, its build cache and the registry.

```toml
[relay]
name = "My Relay"                              # shown in clients via NIP-11
description = "A friendly relay for everyone"
private_key = ""                               # MUST stay empty; inject it below
public_url = "wss://<your-app-name>.fly.dev"   # required for NIP-42/62/98
```

Generate the key locally, then store it as a Fly secret (the value is injected at runtime by `NOSTRFY_RELAY_PRIVATE_KEY`):

```sh
tmpdir="$(mktemp -d)"
nostrfy --config "$tmpdir/nostrfy.toml" init
nostrfy --config "$tmpdir/nostrfy.toml" genkey
# copy the printed key once:
fly secrets set NOSTRFY_RELAY_PRIVATE_KEY=<printed-key>
rm -rf "$tmpdir"
```

- `public_url` **must** match your app name — without it, NIP-42 AUTH, NIP-62 vanish and the NIP-86 management API will not work
- `fly secrets set NOSTRFY_RPC_MANAGEMENT_TOKEN=...` / `NOSTRFY_LIVEKIT_API_SECRET=...` / `NOSTRFY_BLOSSOM_S3_SECRET_KEY=...` work the same way
- Everything else can stay at the defaults

### 4. Deploy

```sh
fly deploy
```

Fly builds the image (a few minutes — the binary download is fast, the image is small), creates a machine and runs the liveness check against `/live`.

## Verify

```sh
# log line: "relay listening on ws://0.0.0.0:8080"
fly logs

# NIP-11 information document over the public address
curl https://<your-app-name>.fly.dev/

# point your Nostr client at wss://<your-app-name>.fly.dev
```

## Scaling and updates

- **Update the relay**: edit `deploy/nostrfy.container.toml` for non-secret settings and `fly deploy` again — the image installs the **latest** GitHub release binary, so an update is a simple redeploy. Secrets stay in `fly secrets`.
- **Pin a version**: `docker build --build-arg NOSTRFY_VERSION=v0.1.3 ...`
- **Scale**: the relay is a **single machine per database**. LMDB is single-writer; do not clone the machine to share a volume (`fly machines clone` would fail to lock the database or, on a filesystem without working locks, corrupt the derived state). Run one machine per volume; for read scale use a separate relay/database.
- **Metrics**: Fly collects the `/metrics` endpoint (see `[metrics]` in `fly.toml`) and shows it in the Fly dashboard under Metrics

## Customizing the configuration

The image reads `/etc/nostrfy/nostrfy.toml`, baked from `deploy/nostrfy.container.toml`. Customize it in one of two ways:

1. **Edit `deploy/nostrfy.container.toml` in the repository** for non-secret settings (name, description, public_url, limits) and redeploy
2. **Mount your own config** if you need a fully custom file; keep it outside the image and mount it at `/etc/nostrfy/nostrfy.toml`

Secrets do **not** belong in either file. Use `fly secrets set NOSTRFY_RELAY_PRIVATE_KEY=...` (and the other `NOSTRFY_*` names) or a mounted secret store. Every option is documented in the [Configuration reference](../CONFIGURATION.md).

## Notes

- **Always-on by design**: `auto_stop_machines = false` in `fly.toml` — a relay must never be stopped during idle periods
- The container runs the relay in **foreground mode** (`nostrfy start --foreground`); logs go to stdout/stderr and are collected by Fly
- TLS is terminated by Fly; the relay itself serves plain WebSocket on port 8080
- **Trusted proxy**: Fly's edge connects over the private 6PN range. The template sets `server.trusted_proxies = ["fdaa::/16", "127.0.0.1/32", "::1/128"]`; leaving it empty makes every client share the edge address, so the per-IP connection cap (64) applies relay-wide and `blockip`/rate limits hit everyone. Never add an address clients can reach directly.
- **Shutdown grace**: `fly.toml` sets `kill_timeout = "35s"`. The relay's graceful shutdown budget is 27s; Fly's 5s default would SIGKILL while WebSockets drain and the final batch/snapshots flush.
- **Blossom media host**: to serve the Blossom server too, set `blossom.host = "media.example.com"` in the config, add `media.example.com` as an **additional hostname** of the same Fly app (fly.toml `[[services]] http_options.allowed_http_hostnames` or `fly hostnames`), and add the `media.` TLS certificate in the Fly dashboard — the relay splits the hosts internally (like `server.api_host`)