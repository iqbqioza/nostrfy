# Deploying nostrfy on Microsoft Azure

Options: **VM** (recommended), or **Container Apps**.

## Option 1: Virtual Machine (recommended)

1. **Create a VM**: Ubuntu 24.04 LTS, `Standard_B1s` (1 GB) or `Standard_B2s` (2 GB) to start. Choose a region close to your users.
2. **Network security group (NSG)**: add an inbound rule for TCP `8080` (and `443` for TLS). Restrict the SSH rule to your IP.
3. **SSH in** and follow the generic [VPS guide](vps.md):

```sh
ssh <user>@<public-ip>
curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrfy/main/install.sh | sh
sudo mkdir -p /etc/nostrfy
sudo curl -fsSL -o /etc/nostrfy/nostrfy.toml \
  https://raw.githubusercontent.com/iqbqioza/nostrfy/main/deploy/nostrfy.toml
sudo nano /etc/nostrfy/nostrfy.toml                 # set name, public_url, private_key
sudo curl -fsSL -o /etc/systemd/system/nostrfy.service \
  https://raw.githubusercontent.com/iqbqioza/nostrfy/main/deploy/nostrfy.service
sudo systemctl daemon-reload
sudo systemctl enable --now nostrfy
```

4. **Verify**:

```sh
curl http://<public-ip>:8080/health
```

5. **Add TLS (`wss://`)** with certbot + nginx (as in the [VPS guide](vps.md)) or an Azure Application Gateway with a certificate.

> **Note**: an Azure VM's public IP can change on deallocation — use a **static public IP** so `relay.public_url` stays valid.

## Option 2: Azure Container Apps

Container Apps builds from the repository `Dockerfile` (which downloads the pre-built release binary):

1. **Create a Container App** from the GitHub repo (or push the image to ACR).
2. **Port**: set the container port to `8080`.
3. **Memory**: at least 1 GB.
4. **Persistent storage**: mount an **Azure Storage file share** at `/data` for the LMDB data.
5. **TLS**: Container Apps provides `https://` on the app URL — set `relay.public_url = "wss://<app>.<region>.azurecontainerapps.io"` (or a custom domain).

> **Note**: set **min replicas = 1** — a relay must never scale to zero. The baked `deploy/nostrfy.container.toml` can be replaced by mounting your own `nostrfy.toml` at `/etc/nostrfy/nostrfy.toml`.