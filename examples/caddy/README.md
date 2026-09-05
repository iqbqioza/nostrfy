# Caddy + nostrd templates
#
# Caddyfile      — one relay behind automatic HTTPS
# Caddyfile.multi— several relays (and a Blossom media server) on one
#                  machine, each with its own hostname and certificate
# relay-1.toml   — nostrd config for the first relay (general-purpose
#                  + Blossom for media.example.com)
# relay-2.toml   — nostrd config for the second relay (groups-focused)
#
# The relay itself never terminates TLS: Caddy does. nostrd only
# listens on 127.0.0.1 and trusts the X-Forwarded-Proto header Caddy
# sets (README: "Works behind TLS-terminating proxies").
#
# --- Single relay ----------------------------------------------------------
#
# 1. Install Caddy (https://caddyserver.com/docs/install):
#      apt install caddy          # Debian/Ubuntu
#      pkg install caddy          # FreeBSD
#
# 2. Copy the configs:
#      cp Caddyfile /etc/caddy/Caddyfile
#      cp examples/relay-basic.toml nostrd.toml   # or relay-1.toml
#      nostrd check
#
# 3. Edit the hostname in /etc/caddy/Caddyfile and set relay.public_url
#    + relay.private_key (nostrd genkey) in nostrd.toml.
#
# 4. Start both services (systemd: `systemctl enable --now caddy`).
#    Caddy obtains the TLS certificate automatically on first request;
#    open only TCP/80 and TCP/443 in the firewall.
#
# 5. Point clients at wss://relay.example.com.
#
# --- Several relays on one server ------------------------------------------
#
# Each relay is a separate nostrd process with its own config, port and
# database. The rule of thumb: one process = one relay = one hostname
# (the only in-process multiplexing is the Blossom media server, which
# is routed by the Host header via [blossom] host).
#
#   1. cp Caddyfile.multi /etc/caddy/Caddyfile
#   2. cp relay-1.toml relay-2.toml <working-dir>/     # two processes
#   3. Set the three hostnames in the Caddyfile, the public_url +
#      private_key in both toml files, and start both relays.
#   4. systemctl reload caddy   # pick up the Caddyfile changes
#
# Backups, disk space and upgrades apply per relay (each has its own
# database and logs). To stop one relay, `nostrd --config relay-N.toml
# stop` — the other keeps running.
#
# --- Troubleshooting ------------------------------------------------------
#
# * Clients fail to connect but the relay responds on 127.0.0.1:8080:
#   check the hostname in the Caddyfile and that Caddy is running
#   (caddy validate --config /etc/caddy/Caddyfile).
# * "Server: nginx" or mixed content warnings: make sure clients use
#   wss://, not ws://.
# * WebSocket connections drop after ~60 s: increase ws_idle_timeout_secs
#   in [limits] (some clients send no keep-alive).
# * The management API (NIP-86) is bound to 127.0.0.1 only — do NOT
#   expose it through Caddy; it is not covered by the templates.