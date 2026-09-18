#!/bin/sh
# Performance smoke test: builds the release relay and bench client, starts
# the relay on a throwaway config/database, runs the two fast bench
# scenarios and asserts conservative floors. The point is catching
# order-of-magnitude throughput/fan-out regressions on shared CI runners —
# it is not a benchmark of the host.
#
# Usage: bash scripts/perf_smoke.sh (or ./scripts/perf_smoke.sh).
set -eu

# Conservative floors: a shared CI runner is noisy and slow, so the ingest
# floor sits far below any healthy machine (~20k ev/s locally), and the
# 500 ms fan-out settle delay built into the bench is what the 100% check
# relies on. Fan-out misses would mean a real delivery bug.
MIN_INGEST_EV_S=300
INGEST_EVENTS=2000
FANOUT_SUBSCRIBERS=60
FANOUT_PUBLISHES=200
READY_TIMEOUT_SECS=60
BENCH_TIMEOUT_SECS=180

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN="$ROOT/target/release/nostrfy"
BENCH="$ROOT/target/release/examples/bench"

TMPDIR=$(mktemp -d)
RELAY_PID=

cleanup() {
    if [ -n "$RELAY_PID" ]; then
        kill "$RELAY_PID" 2>/dev/null || true
        wait "$RELAY_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

fail() {
    echo "perf-smoke: FAIL: $*" >&2
    exit 1
}

# A random high port avoids colliding with parallel jobs. If something else
# already holds it, the relay exits at bind time and the liveness check
# below catches it before the bench can connect to a foreign listener.
if [ -r /dev/urandom ]; then
    RAND=$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')
    PORT=$((20000 + RAND % 20000))
else
    PORT=$((20000 + $$ % 20000))
fi
URL="ws://127.0.0.1:$PORT"

CONFIG="$TMPDIR/nostrfy.toml"
mkdir -p "$TMPDIR/data"
cat >"$CONFIG" <<EOF
[relay]
name = "perf-smoke"
# The bench's fanout publisher waits for the relay's first frame (the
# default AUTH challenge) as its handshake liveness check, so leave
# send_auth_challenge at its default.

[server]
host = "127.0.0.1"
port = $PORT
metrics_enabled = false

[limits]
# 60 fan-out subscribers, the publisher and the ingest connection.
max_connections_per_ip = 128

[database]
path = "$TMPDIR/data"

[daemon]
pid_file = "$TMPDIR/nostrfy.pid"
log_file = "$TMPDIR/nostrfy.log"
stats_file = "$TMPDIR/nostrfy.stats.json"
EOF

echo "perf-smoke: building release binary and bench example"
cargo build --release --bins --examples --manifest-path "$ROOT/Cargo.toml"

ready() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/health" 2>/dev/null
    elif command -v nc >/dev/null 2>&1; then
        nc -z 127.0.0.1 "$PORT" 2>/dev/null
    else
        # bash's /dev/tcp (the script is run with bash in CI).
        (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null
    fi
}

echo "perf-smoke: starting relay on $URL (config $CONFIG)"
"$BIN" --config "$CONFIG" start --foreground >"$TMPDIR/relay.out" 2>&1 &
RELAY_PID=$!

i=0
while [ "$i" -lt "$READY_TIMEOUT_SECS" ]; do
    if ! kill -0 "$RELAY_PID" 2>/dev/null; then
        cat "$TMPDIR/relay.out" >&2 || true
        fail "relay exited during startup"
    fi
    if ready; then
        echo "perf-smoke: relay ready after ${i}s"
        break
    fi
    sleep 1
    i=$((i + 1))
done
[ "$i" -lt "$READY_TIMEOUT_SECS" ] || {
    cat "$TMPDIR/relay.out" >&2 || true
    fail "relay was not ready within ${READY_TIMEOUT_SECS}s"
}

run_bench() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$BENCH_TIMEOUT_SECS" "$BENCH" "$@"
    else
        "$BENCH" "$@"
    fi
}

echo "perf-smoke: ingest $INGEST_EVENTS"
INGEST_OUT=$(run_bench "$URL" ingest "$INGEST_EVENTS") || fail "bench ingest failed"
printf '%s\n' "$INGEST_OUT"
RATE=$(printf '%s\n' "$INGEST_OUT" | sed -n 's/.*= \([0-9][0-9.]*\) ev\/s.*/\1/p' | head -n 1)
[ -n "$RATE" ] || fail "could not parse the ingest rate from the bench output"
awk -v rate="$RATE" -v floor="$MIN_INGEST_EV_S" 'BEGIN { exit !(rate >= floor) }' \
    || fail "ingest rate ${RATE} ev/s is below the ${MIN_INGEST_EV_S} ev/s floor"
ACCEPTED=$(printf '%s\n' "$INGEST_OUT" | sed -n 's/.*(\([0-9]*\) ok, \([0-9]*\) accepted).*/\2/p' | head -n 1)
[ "$ACCEPTED" = "$INGEST_EVENTS" ] || fail "the relay accepted ${ACCEPTED:-?}/${INGEST_EVENTS} events"

echo "perf-smoke: fanout $FANOUT_SUBSCRIBERS subscribers x $FANOUT_PUBLISHES publishes"
FANOUT_OUT=$(run_bench "$URL" fanout "$FANOUT_SUBSCRIBERS" "$FANOUT_PUBLISHES") || fail "bench fanout failed"
printf '%s\n' "$FANOUT_OUT"
DELIVERED=$(printf '%s\n' "$FANOUT_OUT" | awk '/deliveries / { sub(/.*deliveries /, ""); print }')
[ -n "$DELIVERED" ] || fail "could not parse the deliveries from the bench output"
TOTAL=$((FANOUT_SUBSCRIBERS * FANOUT_PUBLISHES))
[ "$DELIVERED" = "$TOTAL/$TOTAL" ] || fail "fanout delivered $DELIVERED, expected $TOTAL/$TOTAL"

echo "perf-smoke: OK (ingest ${RATE} ev/s >= ${MIN_INGEST_EV_S}; fanout ${DELIVERED} deliveries)"
