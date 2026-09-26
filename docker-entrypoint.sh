#!/bin/sh
# Container entrypoint: generate a default config on first start, then run
# the relay in the foreground. Mount your own file at
# /etc/nostrfy/nostrfy.toml to skip generation entirely.
set -eu

CONFIG="/etc/nostrfy/nostrfy.toml"

if [ ! -s "${CONFIG}" ]; then
    echo "no config at ${CONFIG}: writing defaults with 'nostrfy init'" >&2
    nostrfy --config "${CONFIG}" init
fi

# Allow `docker run <image> <nostrfy-args...>` to replace the CMD while
# keeping the init behavior above.
if [ "$1" = "nostrfy" ]; then
    shift
    exec nostrfy "$@"
fi
exec "$@"
