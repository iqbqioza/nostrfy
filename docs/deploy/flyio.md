# Deploying nostrfy to Fly.io

This guide deploys nostrfy to [Fly.io](https://fly.io) in a few minutes. The repository ships a ready-made template:

| File | Purpose |
| --- | --- |
| `Dockerfile` | Container image — **downloads the pre-built release binary** from the GitHub release assets (x86_64 / aarch64, chosen by the build architecture) and verifies its sha256 checksum. No compilation happens on Fly |
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

Edit `deploy/nostrfy.container.toml` before deploying:

```toml
[relay]
name = "My Relay"                              # shown in clients via NIP-11
description = "A friendly relay for everyone"
private_key = "..."                            # required for NIP-29 groups
public_url = "wss://<your-app-name>.fly.dev"   # required for NIP-42/62/98
```

- `private_key`: generate locally with `nostrfy genkey` (against a temporary config) and paste the key, or generate one with any Nostr tool
- `public_url` **must** match your app name — without it, NIP-42 AUTH, NIP-62 vanish and the NIP-86 management API will not work
- Everything else can stay at the defaults

### 4. Deploy

```sh
fly deploy
```

Fly builds the image (a few minutes — the binary download is fast, the image is small), creates a machine and runs the health check against `/health`.

## Verify

```sh
# log line: "relay listening on ws://0.0.0.0:8080"
fly logs

# NIP-11 information document over the public address
curl https://<your-app-name>.fly.dev/

# point your Nostr client at wss://<your-app-name>.fly.dev
```

## Scaling and updates

- **Update the relay**: edit `deploy/nostrfy.container.toml` and `fly deploy` again — the image always downloads the **latest** GitHub release binary, so an update is a simple redeploy
- **Pin a version**: `docker build --build-arg NOSTRFY_VERSION=v0.1.2 ...` or change the `ARG` in the Dockerfile
- **Scale**: the relay is a single machine by default. `fly machines clone <id>` creates a second machine; both share the volume (Fly volumes support multiple machines in the same region)
- **Metrics**: Fly collects the `/metrics` endpoint (see `[metrics]` in `fly.toml`) and shows it in the Fly dashboard under Metrics

## Customizing the configuration

The image reads `/etc/nostrfy/nostrfy.toml`, baked from `deploy/nostrfy.container.toml`. Two ways to customize:

1. **Edit `deploy/nostrfy.container.toml` in the repository** and redeploy (simplest)
2. **Mount your own config**: build a fork of the image that copies your config file over `/etc/nostrfy/nostrfy.toml`

Every option is documented in the [Configuration reference](../CONFIGURATION.md).

## Notes

- **Always-on by design**: `auto_stop_machines = false` in `fly.toml` — a relay must never be stopped during idle periods
- The container runs the relay in **foreground mode** (`nostrfy start --foreground`); logs go to stdout/stderr and are collected by Fly
- TLS is terminated by Fly; the relay itself serves plain WebSocket on port 8080
- **Blossom media host**: to serve the Blossom server too, set `blossom.host = "media.example.com"` in the config, add `media.example.com` as an **additional hostname** of the same Fly app (fly.toml `[[services]] http_options.allowed_http_hostnames` or `fly hostnames`), and add the `media.` TLS certificate in the Fly dashboard — the relay splits the hosts internally (like `server.api_host`)