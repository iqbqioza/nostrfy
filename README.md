# nostrfy

<p align="center">
  <img src="https://nostrfy.org/og-image.png" alt="nostrfy — a minimal and stable Nostr relay server" width="100%">
</p>

<p align="center">
  <a href="https://github.com/iqbqioza/nostrfy/actions/workflows/ci.yml"><img src="https://github.com/iqbqioza/nostrfy/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/iqbqioza/nostrfy/actions/workflows/release.yml"><img src="https://github.com/iqbqioza/nostrfy/actions/workflows/release.yml/badge.svg" alt="Release"></a>
  <a href="https://github.com/sponsors/iqbqioza"><img src="https://img.shields.io/github/sponsors/iqbqioza" alt="GitHub Sponsors"></a>
</p>

<p align="center">
  <a href="https://nostrfy.org/">Official website</a>
</p>

**High-performance Nostr relay engine written in Rust. Fast, memory-efficient, and built for modern relays.**

> [!TIP]
> Live instance running at **wss://relay.nostrfy.org**.

## Install in one line

No cloning, no compiling — downloads the pre-built binary for your platform, verifies its checksum, and installs it:

```sh
curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrfy/main/install.sh | sh
```

### Migrate from strfry?

Bring your existing database with one command (dry-run first, then import):

```sh
nostrfy migrate-strfry --dry-run
nostrfy migrate-strfry
```

See the [step-by-step migration guide](docs/MIGRATING-FROM-STRFRY.md).

## Run in one minute

```sh
nostrfy init          # write a default nostrfy.toml and exit
nostrfy start         # start as a daemon (--foreground to stay in the shell)
nostrfy stats         # check it is up
```

Point your Nostr client at `ws://<host>:8080` (or `wss://<domain>` behind a TLS proxy). Copy a ready-made template from [`examples/`](examples/) for chat, DMs, groups, search, or tiny-VPS setups — then `nostrfy check` it.

Deploying to Fly.io, AWS, GCP, Azure, Digital Ocean, or any VPS? See the [deployment guides](docs/deploy/README.md).

## What you get

- **Never go down** — overload protection, dedicated reader threads, panic containment, and strict resource bounds ([architecture](docs/MANUAL.md#14-large-scale-deployments)).
- **Spec-complete** — all relay-side NIPs ([support table](docs/MANUAL.md#8-supported-nips)), plus NIP-94 file metadata and a built-in Blossom media server ([guide](docs/MANUAL.md#11-blossom-file-server-media-hosting)).
- **REST API** at `/api/v1` on its own reader thread ([reference](docs/API.md)).
- **Everything configurable** via `nostrfy.toml`, validated by `nostrfy check` ([reference](docs/CONFIGURATION.md)).

## Documentation

| Document | Contents |
| --- | --- |
| [Manual](docs/MANUAL.md) | Installation, configuration, operation, NIPs, groups, LiveKit, Blossom, logs |
| [Configuration reference](docs/CONFIGURATION.md) | Every `nostrfy.toml` option, validation rules, reload behavior |
| [HTTP REST API reference](docs/API.md) | `/api/v1` endpoints, parameters, pagination, errors |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common errors and fixes |
| [Deployment guides](docs/deploy/README.md) | Fly.io, Digital Ocean, AWS, GCP, Azure, any VPS |
| [Migrating from strfry](docs/MIGRATING-FROM-STRFRY.md) | Step-by-step database migration |

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
