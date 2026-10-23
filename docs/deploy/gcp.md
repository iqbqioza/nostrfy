# Deploying nostrfy on Google Cloud

Options: **Compute Engine** (VM, recommended) or **Cloud Run** (containers).

## Option 1: Compute Engine (recommended)

1. **Create a VM**: Ubuntu 24.04 LTS (or Debian), `e2-small` (2 GB) is enough to start. Choose a region close to your users.
2. **Firewall rule**: allow inbound TCP `8080` (and `443` for TLS). Under **Network → Firewall**, create a rule with the target tags you assigned to the VM.
3. **SSH in** (the console's SSH button works) and follow the generic [VPS guide](vps.md):

```sh
curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrfy/main/install.sh | sudo env INSTALL_DIR=/usr/local/bin sh
sudo useradd --system --create-home --home /var/lib/nostrfy nostrfy
sudo install -d -o nostrfy -g nostrfy -m 0750 /etc/nostrfy
sudo curl -fsSL -o /etc/nostrfy/nostrfy.toml \
  https://raw.githubusercontent.com/iqbqioza/nostrfy/main/deploy/nostrfy.toml
sudo chown nostrfy:nostrfy /etc/nostrfy/nostrfy.toml
sudo chmod 600 /etc/nostrfy/nostrfy.toml
sudo nano /etc/nostrfy/nostrfy.toml                 # set name, public_url, private_key
sudo curl -fsSL -o /etc/systemd/system/nostrfy.service \
  https://raw.githubusercontent.com/iqbqioza/nostrfy/main/deploy/nostrfy.service
sudo systemctl daemon-reload
sudo systemctl enable --now nostrfy
```

4. **Reserve a static IP** (External IP → Reserve) so `public_url` stays valid across reboots.
5. **Verify**:

```sh
curl http://<external-ip>:8080/health
```

6. **Add TLS (`wss://`)** with certbot + nginx (as in the [VPS guide](vps.md)) or a GCP load balancer with a managed certificate.

## Option 2: Cloud Run (container)

Cloud Run builds from the repository `Dockerfile` (which downloads the pre-built release binary):

1. **Create a service from the GitHub repo** (or push the image to Artifact Registry).
2. **Port**: set the container port to `8080`.
3. **Allocate memory**: at least 512 MB (LMDB + the async runtime).
4. **Persistent storage**: LMDB needs a **local block device** (a Compute Engine persistent disk). Cloud Run's Filestore/GCS FUSE mounts are network filesystems; they do not provide the POSIX locking/`mmap` behavior LMDB requires and can corrupt the database. For production, run on Compute Engine with a persistent disk (the recommended option above). If you must use a container, mount a block-backed volume, not GCS FUSE.
5. **TLS**: Cloud Run provides `https://` automatically — set `relay.public_url = "wss://<service>.a.run.app"` (or your custom domain).
6. **Secrets**: inject `NOSTRFY_RELAY_PRIVATE_KEY` (and the other `NOSTRFY_*` names) with Secret Manager / the service's secret environment. Never put the key in the baked `deploy/nostrfy.container.toml`.

> **Note**: Cloud Run scales to zero by default — for a relay, set **min instances = 1** so it never goes cold. A non-secret custom config can be mounted at `/etc/nostrfy/nostrfy.toml`.