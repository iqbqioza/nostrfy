# nostrfy — generic container image (Docker, Podman, Fly.io, any OCI runtime)
#
# The binary is NOT compiled here: it is installed with install.sh from the
# GitHub release assets built by the Release workflow (the script detects
# the architecture and verifies the sha256 checksum).
#
#   docker build -t nostrfy .
#   docker run -d --name nostrfy -p 8080:8080 -v nostrfy-data:/data nostrfy
#
# To pin a specific release instead of the latest:
#   docker build --build-arg NOSTRFY_VERSION=v0.1.3 -t nostrfy .
#
# The relay runs in the FOREGROUND (`start --foreground`); daemon mode is
# not used in containers. On first start with an empty config, `nostrfy
# init` writes the defaults (override by mounting your own file at
# /etc/nostrfy/nostrfy.toml). Terminate TLS in front (reverse proxy / CDN):
# the container itself serves plain WS on 0.0.0.0:8080.

# syntax=docker/dockerfile:1

FROM debian:trixie-slim

ARG NOSTRFY_VERSION

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10000 --home-dir /data --create-home nostr

# Install the release binary (auto-detects linux x86_64/aarch64, verifies
# sha256). For Apache-2.0 compliance the license texts and NOTICE published
# as release assets travel in the image (the image redistributes the binary,
# so it must carry them).
RUN if [ -n "${NOSTRFY_VERSION}" ]; then \
      BASE="https://github.com/iqbqioza/nostrfy/releases/download/${NOSTRFY_VERSION}"; \
    else \
      BASE="https://github.com/iqbqioza/nostrfy/releases/latest/download"; \
    fi \
    && export VERSION="${NOSTRFY_VERSION}" INSTALL_DIR=/usr/local/bin \
    && curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrfy/main/install.sh | sh \
    && mkdir -p /usr/share/licenses/nostrfy \
    && curl -fsSL "${BASE}/LICENSE-MIT" -o /usr/share/licenses/nostrfy/LICENSE-MIT \
    && curl -fsSL "${BASE}/LICENSE-APACHE" -o /usr/share/licenses/nostrfy/LICENSE-APACHE \
    && curl -fsSL "${BASE}/NOTICE" -o /usr/share/licenses/nostrfy/NOTICE

COPY deploy/nostrfy.container.toml /etc/nostrfy/nostrfy.toml
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN mkdir -p /data /etc/nostrfy \
    && chown -R nostr:nostr /data /etc/nostrfy
VOLUME ["/data"]
EXPOSE 8080
USER nostr
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["nostrfy", "--config", "/etc/nostrfy/nostrfy.toml", "start", "--foreground"]
