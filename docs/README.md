# nostrfy Documentation

Welcome! This documentation is a guide for everyone who wants to install and use **nostrfy**, a Nostr relay server — and for operators who hit a snag during day-to-day operation.

The guides are written to be friendly and practical, with real command examples and explanations of error messages, so you are never left guessing.

## Table of Contents

| Document | Contents | Read this when... |
| --- | --- | --- |
| [Manual (MANUAL.md)](MANUAL.md) | The complete guide: installation, configuration, operation, NIP support, REST API, NIP-86 management API | You are getting started, changing settings, or want to know what the relay can do |
| [Configuration Reference (CONFIGURATION.md)](CONFIGURATION.md) | Every option of `nostrfy.toml` with defaults, validation rules and a full example | You want to tune the relay or check what a setting does |
| [HTTP REST API Reference (API.md)](API.md) | The `/api/v1` endpoint: paths, parameters, responses, pagination, errors | You want to query events from scripts or other programs |
| [Troubleshooting (TROUBLESHOOTING.md)](TROUBLESHOOTING.md) | Common errors and their step-by-step fixes | You hit an error or something behaves unexpectedly |

## Quick Start (30-second guide)

```bash
# 1. Build (requires Rust)
cargo build --release

# 2. Create a config file
./target/release/nostrfy --config nostrfy.toml init

# 3. Edit the config file (relay name, port, ...)
#    Open nostrfy.toml in your text editor and adjust it

# 4. Validate the config (catches mistakes before starting)
./target/release/nostrfy --config nostrfy.toml check

# 5. Start the relay
./target/release/nostrfy --config nostrfy.toml start

# 6. Verify it is up
curl http://127.0.0.1:8080/health
# => If it prints {"status":"ok"} you are done!
```

- For the full details, see the [Manual](MANUAL.md)
- If something went wrong, see [Troubleshooting](TROUBLESHOOTING.md)

## Keeping this documentation up to date

This documentation lives in the `docs/` directory of the repository. If you find a mistake or an improvement, please consider submitting a fix.