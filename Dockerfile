# nostrfy — Fly.io container image
#
# The binary is NOT compiled here: it is downloaded from the GitHub
# release assets built by the Release workflow (x86_64 and aarch64) and
# verified against its sha256 checksum. The relay runs in the FOREGROUND
# (`start --foreground`) because Fly expects the app process to stay in
# the foreground; daemon mode is not used on Fly.
#
# Build with buildx so TARGETARCH is set automatically:
#   docker buildx build --platform linux/amd64,linux/arm64 .
# (fly deploy does this for you.)
#
# To pin a specific release instead of the latest:
#   docker build --build-arg NOSTRFY_VERSION=v0.1.0-alpha-01 .

# syntax=docker/dockerfile:1

FROM debian:bookworm-slim

ARG TARGETARCH
ARG NOSTRFY_VERSION

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && case "${TARGETARCH}" in \
         amd64) ASSET="nostrfy-linux-x86_64" ;; \
         arm64) ASSET="nostrfy-linux-aarch64" ;; \
         *) echo "error: unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && if [ -n "${NOSTRFY_VERSION}" ]; then \
         BASE="https://github.com/iqbqioza/nostrfy/releases/download/${NOSTRFY_VERSION}"; \
       else \
         BASE="https://github.com/iqbqioza/nostrfy/releases/latest/download"; \
       fi \
    && echo "downloading ${BASE}/${ASSET}" \
    && curl -fsSL "${BASE}/${ASSET}" -o "/tmp/${ASSET}" \
    && curl -fsSL "${BASE}/${ASSET}.sha256" -o "/tmp/${ASSET}.sha256" \
    && (cd /tmp && sha256sum -c "${ASSET}.sha256") \
    && install -m 0755 "/tmp/${ASSET}" /usr/local/bin/nostrfy \
    && rm -f "/tmp/${ASSET}" "/tmp/${ASSET}.sha256" \
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/*

# The container configuration template (edit deploy/nostrfy.container.toml
# before building to set the relay name, public_url and private_key).
COPY deploy/nostrfy.container.toml /etc/nostrfy/nostrfy.toml

# LMDB data lives on the Fly volume mounted at /data (see fly.toml).
RUN mkdir -p /data /etc/nostrfy
VOLUME ["/data"]
EXPOSE 8080
CMD ["nostrfy", "--config", "/etc/nostrfy/nostrfy.toml", "start", "--foreground"]