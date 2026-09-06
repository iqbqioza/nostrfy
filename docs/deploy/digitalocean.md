# Deploying nostrfy on Digital Ocean

Two options: a **Droplet** (VM, simplest) or the **App Platform** (containers).

## Option 1: Droplet (recommended)

1. **Create a Droplet**: Ubuntu 24.04 LTS, any size (1 GB RAM is enough to start). A droplet in a region close to your users lowers latency.
2. **SSH in** and follow the generic [VPS guide](vps.md):

```sh
ssh root@<droplet-ip>
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

3. **Open the port** in the Droplet firewall (the [Digital Ocean Cloud Firewall](https://www.digitalocean.com/community/tutorials/how-to-configure-a-digitalocean-cloud-firewall) is recommended): allow inbound TCP `8080` (and `443` if you add TLS).
4. **Verify**:

```sh
curl http://<droplet-ip>:8080/health
```

5. **Add TLS (`wss://`)** with certbot + nginx, or [Digital Ocean's managed load balancer](https://docs.digitalocean.com/products/networking/load-balancers/) with a certificate — then set `relay.public_url = "wss://relay.example.com"` and restart.

## Option 2: App Platform (container)

The App Platform builds from the repository `Dockerfile` (which downloads the pre-built release binary):

1. **Connect your GitHub repo** and create an app from it.
2. **Port**: set the HTTP port to `8080` (the relay listens there).
3. **Persistent disk**: mount a volume at `/data` (LMDB data lives there — without it, data is lost on every deploy).
4. **Env**: the `deploy/nostrfy.container.toml` baked into the image can be replaced by mounting your own config at `/etc/nostrfy/nostrfy.toml` (create a fork that copies it, or use a Dockerfile `COPY` in your own repo).
5. **TLS**: App Platform provides `https://` automatically for the app domain — set `relay.public_url` accordingly.

## Both options

- Updates: re-run `install.sh` + `systemctl restart nostrfy` (Droplet), or push to the connected repo (App Platform).
- All configuration is documented in the [Configuration reference](../CONFIGURATION.md).