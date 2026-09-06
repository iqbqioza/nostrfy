#!/usr/bin/env bash
#
# install.sh — download and install the nostrfy relay server.
#
# Downloads the binary built by the GitHub Actions release workflow and
# installs it into a directory on PATH. Works without sudo: by default the
# binary goes to a user-writable directory (~/.local/bin, ~/bin, or
# ~/.cargo/bin, in that order — the first one already on PATH wins).
#
# Usage:
#   ./install.sh                  # install the latest release
#   VERSION=v0.1.0-alpha-01 ./install.sh   # install a specific release
#   INSTALL_DIR=/usr/local/bin sudo ./install.sh   # system-wide install
#   ./install.sh --force          # overwrite an existing binary without asking
#
# The downloaded binary is verified against the release's sha256 checksum.

set -eu

REPO="iqbqioza/nostrfy"
VERSION="${VERSION:-}"          # empty = latest release
INSTALL_DIR="${INSTALL_DIR:-}"  # empty = auto-detect (see below)
FORCE=0

usage() {
  cat <<'EOF'
install.sh — download and install the nostrfy relay server.

Usage:
  ./install.sh                         install the latest release
  VERSION=v0.1.0 ./install.sh          install a specific release
  INSTALL_DIR=/usr/local/bin sudo ./install.sh   system-wide install
  ./install.sh --force                 overwrite without asking

One-liner (no clone needed):
  curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrfy/main/install.sh | sh
  curl -fsSL https://raw.githubusercontent.com/iqbqioza/nostrfy/main/install.sh | sh -s -- --force
EOF
}

for arg in "$@"; do
  case "$arg" in
    -f|--force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 1 ;;
  esac
done

# --- download tool ----------------------------------------------------------

if command -v curl >/dev/null 2>&1; then
  download() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  download() { wget -qO "$2" "$1"; }
else
  echo "error: neither curl nor wget is available" >&2
  exit 1
fi

# --- OS and architecture ---------------------------------------------------

case "$(uname -s)" in
  Linux)   OS="linux" ;;
  FreeBSD) OS="freebsd" ;;
  *)
    echo "error: unsupported OS: $(uname -s)" >&2
    echo "supported: Linux, FreeBSD" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64 | amd64)
    if [ "$OS" = "linux" ]; then ASSET="nostrfy-linux-x86_64"; else ASSET="nostrfy-freebsd-x86_64"; fi
    ;;
  aarch64 | arm64)
    [ "$OS" = "linux" ] || { echo "error: FreeBSD is only packaged for x86_64" >&2; exit 1; }
    ASSET="nostrfy-linux-aarch64"
    ;;
  *)
    echo "error: unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

if [ -n "$VERSION" ]; then
  BASE="https://github.com/$REPO/releases/download/$VERSION"
else
  # GitHub redirects /latest/download/<asset> to the latest release's asset.
  BASE="https://github.com/$REPO/releases/latest/download"
fi
URL="$BASE/$ASSET"
URL_SHA="$BASE/$ASSET.sha256"

# --- install directory ------------------------------------------------------

if [ -z "$INSTALL_DIR" ]; then
  for dir in "$HOME/.local/bin" "$HOME/bin" "$HOME/.cargo/bin"; do
    if [ -d "$dir" ] && printf ':%s:' "$PATH" | grep -q ":$dir:"; then
      INSTALL_DIR="$dir"
      break
    fi
  done
  INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
fi

if ! mkdir -p "$INSTALL_DIR"; then
  echo "error: cannot create $INSTALL_DIR" >&2
  echo "hint: install with sudo: INSTALL_DIR=/usr/local/bin sudo $0" >&2
  exit 1
fi

TARGET="$INSTALL_DIR/nostrfy"

# --- overwrite confirmation -------------------------------------------------

if [ -e "$TARGET" ]; then
  if [ "$FORCE" -eq 1 ]; then
    echo "overwriting $TARGET (--force)"
  elif [ -t 0 ]; then
    printf "nostrfy already exists at %s. Overwrite it? [y/N] " "$TARGET"
    read -r answer
    case "$answer" in
      y | Y | yes | Yes | YES) echo "overwriting $TARGET" ;;
      *) echo "aborted: $TARGET unchanged" >&2; exit 1 ;;
    esac
  else
    echo "error: nostrfy already exists at $TARGET" >&2
    echo "hint: rerun with --force to overwrite it" >&2
    exit 1
  fi
fi

# --- download and verify ----------------------------------------------------

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "downloading $URL"
# The release's checksum file names the asset, so the downloaded binary
# must keep that name for the verification to line up.
download "$URL" "$tmpdir/$ASSET"
echo "downloading checksum $URL_SHA"
download "$URL_SHA" "$tmpdir/$ASSET.sha256"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$tmpdir" && sha256sum -c "$ASSET.sha256" >/dev/null)
elif command -v shasum >/dev/null 2>&1; then
  (cd "$tmpdir" && shasum -a 256 -c "$ASSET.sha256" >/dev/null)
elif command -v sha256 >/dev/null 2>&1; then
  # FreeBSD's sha256(1) has no -c mode: compare the digest manually.
  actual="$(sha256 -q "$tmpdir/$ASSET")"
  expected="$(awk '{print $1}' "$tmpdir/$ASSET.sha256")"
  if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
    echo "error: checksum mismatch for $ASSET" >&2
    exit 1
  fi
else
  echo "warning: no sha256 verification tool found; skipping checksum check" >&2
fi

chmod +x "$tmpdir/$ASSET"

# --- install ----------------------------------------------------------------

install -m 0755 "$tmpdir/$ASSET" "$TARGET"

"$TARGET" --version

echo
echo "nostrfy installed at $TARGET"
if printf ':%s:' "$PATH" | grep -q ":$INSTALL_DIR:"; then
  echo "run 'nostrfy --help' to get started"
else
  echo "$INSTALL_DIR is not on PATH — add it to your shell profile, e.g.:"
  echo "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.bashrc"
  echo "  source ~/.bashrc"
fi