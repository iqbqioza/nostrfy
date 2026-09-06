# Deploying nostrfy on any VPS (Ubuntu / Debian)

This is the generic guide for a plain Linux VPS (any provider — Hetzner, Vultr, Linode, Contabo, your own server, ...). The other platform guides (Digital Ocean, AWS, GCP, Azure) are shortcuts of this one with their provider-specific firewall steps.

## 1. Install the binary

The `install.sh` script downloads the latest release binary for your architecture (x86_64 / aarch64), verifies its sha256 checksum and installs it into a directory on `PATH` — **no sudo needed for the install itself**:

```sh
curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrfy/main/install.sh | sh
nostrfy --version
```

## 2. Create a configuration

Fetch the template (no repository clone needed) and edit it:

```sh
sudo mkdir -p /etc/nostrfy
sudo curl -fsSL -o /etc/nostrfy/nostrfy.toml \
  https://raw.githubusercontent.com/iqbqioza/nostrfy/main/deploy/nostrfy.toml
sudo nano /etc/nostrfy/nostrfy.toml
```

At minimum, set:

```toml
[relay]
name = "My Relay"
public_url = "wss://relay.example.com"   # your public address
private_key = "..."                      # run `nostrfy genkey` locally and paste the key

[server]
host = "0.0.0.0"                         # already set in the template
port = 8080
```

Generate the secret key with:

```sh
nostrfy --config /tmp/nostrfy-genkey.toml init && nostrfy --config /tmp/nostrfy-genkey.toml genkey
```

(Or mount your own config file instead of the template — any `nostrfy.toml` works.)

## 3. Run as a systemd service

Fetch the hardened unit (no repository clone needed) and start it:

```sh
sudo curl -fsSL -o /etc/systemd/system/nostrfy.service \
  https://raw.githubusercontent.com/iqbqioza/nostrfy/main/deploy/nostrfy.service
sudo systemctl daemon-reload
sudo systemctl enable --now nostrfy
sudo systemctl status nostrfy
```

Logs:

```sh
journalctl -u nostrfy -f
```

## 4. Open the port and verify

Allow TCP 8080 in your firewall (ufw, cloud firewall, host firewall):

```sh
sudo ufw allow 8080/tcp
```

Verify locally and from the outside:

```sh
curl http://localhost:8080/health
curl http://<server-ip>:8080/health        # from your laptop
```

## 5. Put a TLS-terminating proxy in front (for wss://)

The relay serves plain WebSocket on 8080. To expose it as `wss://`, run a reverse proxy on port 443 that terminates TLS. The relay honors `X-Forwarded-Proto`, so no special configuration is needed.

**nginx** (`/etc/nginx/sites-available/relay`):

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Get a free certificate with [certbot](https://certbot.eff.org/) (`sudo certbot --nginx -d relay.example.com`).

**Caddy** (auto TLS, one file):

```
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

**Serving the Blossom media host too**: when `blossom.host = "media.example.com"` is set, that hostname must also reach the same port — the relay splits the hosts internally (like `server.api_host`). Add a second server block / site for it:

```nginx
# nginx
server {
    listen 443 ssl;
    server_name media.example.com;

    ssl_certificate     /etc/letsencrypt/live/media.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/media.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```caddy
# Caddy
media.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Make sure `relay.public_url` in the config matches `wss://relay.example.com`.

## 6. Backups

Stop the relay, copy the data directory, restart:

```sh
sudo systemctl stop nostrfy
sudo tar -czf nostrfy-data-backup.tar.gz /var/lib/nostrfy   # your database.path
sudo systemctl start nostrfy
```

## Updates

```sh
# piped installs never ask for confirmation: use --force to overwrite an
# existing binary (or run the script from a terminal and answer y/N)
curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrfy/main/install.sh | sh -s -- --force
sudo systemctl restart nostrfy
```
