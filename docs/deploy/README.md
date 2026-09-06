# Deploying nostrfy

nostrfy ships pre-built binaries for **x86_64** and **aarch64** (GitHub release assets, checksum-verified by `install.sh`), a container image that **downloads those binaries** (no compilation needed), and deployment guides for the major platforms.

| Platform | Type | Guide |
| --- | --- | --- |
| **Fly.io** | Managed platform (containers, volumes, TLS) | [deploy/flyio.md](flyio.md) |
| **Digital Ocean** | Droplet (VM) or App Platform | [deploy/digitalocean.md](digitalocean.md) |
| **AWS** | EC2 (VM), Lightsail or ECS | [deploy/aws.md](aws.md) |
| **Google Cloud** | Compute Engine (VM) or Cloud Run | [deploy/gcp.md](gcp.md) |
| **Azure** | VM or Container Apps | [deploy/azure.md](azure.md) |
| **Any VPS** | A plain Ubuntu/Debian server | [deploy/vps.md](vps.md) |

## Common building blocks

All the VM guides (Digital Ocean, AWS EC2, GCP, Azure, any VPS) follow the same pattern:

```sh
# 1. Install the latest release binary (no sudo needed for the install itself)
curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrfy/main/install.sh | sh

# 2. Fetch the config template and edit it (no repository clone needed)
sudo mkdir -p /etc/nostrfy
sudo curl -fsSL -o /etc/nostrfy/nostrfy.toml \
  https://raw.githubusercontent.com/iqbqioza/nostrfy/main/deploy/nostrfy.toml
sudo nano /etc/nostrfy/nostrfy.toml                   # set name, public_url, private_key

# 3. Fetch the systemd unit and start the service
sudo curl -fsSL -o /etc/systemd/system/nostrfy.service \
  https://raw.githubusercontent.com/iqbqioza/nostrfy/main/deploy/nostrfy.service
sudo systemctl daemon-reload
sudo systemctl enable --now nostrfy

# 4. Open the port (usually 8080) in the provider's firewall and verify
curl http://localhost:8080/health
```

**Blossom media host**: if `blossom.host` is set, point that hostname at the same port in the TLS proxy too (see the [vps guide](vps.md) for nginx/Caddy blocks).

For VMs, the relay itself serves plain WebSocket on port 8080; a reverse proxy (nginx/Caddy) or the provider's TLS termination in front of it provides `wss://` — nostrfy honors `X-Forwarded-Proto`, so it works behind any TLS-terminating proxy.

## Configuring the relay

Every deployment uses the same `nostrfy.toml` options — the [Configuration reference](../CONFIGURATION.md) explains each one. Before going live, set at least:

```toml
[relay]
name = "My Relay"
public_url = "wss://relay.example.com"   # required for NIP-42 AUTH / NIP-62 / NIP-98
private_key = ""                          # run `nostrfy genkey` and paste the key
```

## Choosing between VM and containers

- **VM (systemd)**: simplest, cheapest, full control. Recommended for most relay deployments.
- **Container**: use the repository `Dockerfile` (downloads the release binary at build time) on Fly.io, Digital Ocean App Platform, AWS ECS, GCP Cloud Run or Azure Container Apps. Persistent storage is required for the LMDB data (`/data`).