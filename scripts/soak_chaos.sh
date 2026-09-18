#!/bin/sh
# Nightly soak + chaos verification for nostrfy.
#
# This is deliberately not part of the pull-request CI: it is slow (release
# build + a multi-minute soak), invasive (SIGKILLs the relay mid-write) and
# inherently timing dependent. It runs from the Nightly workflow
# (.github/workflows/nightly.yml) on a schedule or manual dispatch.
#
# Phase A (soak) drives the release bench in a bounded loop:
#   * `ingest N`             every event must be answered with OK true;
#   * `parallel-ingest C N`  the relay's accepted counter must advance by C*N;
#   * `fanout S P`           every subscriber must receive all P publishes.
# Repeating the fan-out run opens/close ~60 connections each time, so the
# soak also exercises connection churn.
#
# Phase B (chaos) publishes uniquely identifiable events with the
# dependency-free client in scripts/soak_probe.py, which captures the
# relay's OK acks. The relay is then SIGKILLed while fresh ingest traffic
# is in flight, restarted, and every acknowledged event is verified to be
# still queryable through /api/v1/ids/<id>. This repeats CHAOS_CYCLES times.
#
# The relay log is (re)written to $SOAK_ARTIFACT_DIR/relay.log on every
# start so the workflow can upload it even when the script fails. Temporary
# config, database and spool directories are removed on every exit path.
#
# Usage: bash scripts/soak_chaos.sh [PORT]
# Env:
#   SOAK_SECONDS        Phase A duration in seconds (default 120)
#   CHAOS_CYCLES        kill/restart cycles (default 3)
#   CHAOS_EVENTS        acknowledged events published per cycle (default 40)
#   SOAK_PORT           port to use (a positional argument wins)
#   SOAK_ARTIFACT_DIR   relay log directory (default target/soak-artifacts)
#   SOAK_KEEP_TMP=1     keep the temporary directory for debugging
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
BIN="$ROOT/target/release/nostrfy"
BENCH="$ROOT/target/release/examples/bench"
PROBE="$ROOT/scripts/soak_probe.py"

SOAK_SECONDS=${SOAK_SECONDS:-120}
CHAOS_CYCLES=${CHAOS_CYCLES:-3}
CHAOS_EVENTS=${CHAOS_EVENTS:-40}
INGEST_EVENTS=${INGEST_EVENTS:-1000}
PARALLEL_CONNS=${PARALLEL_CONNS:-4}
PARALLEL_EVENTS=${PARALLEL_EVENTS:-250}
FANOUT_SUBSCRIBERS=${FANOUT_SUBSCRIBERS:-60}
FANOUT_PUBLISHES=${FANOUT_PUBLISHES:-200}
CHAOS_TRAFFIC_SECS=${CHAOS_TRAFFIC_SECS:-2}
READY_TIMEOUT_SECS=${READY_TIMEOUT_SECS:-60}
BENCH_TIMEOUT_SECS=${BENCH_TIMEOUT_SECS:-180}
PROBE_TIMEOUT_SECS=${PROBE_TIMEOUT_SECS:-60}
ARTIFACT_DIR=${SOAK_ARTIFACT_DIR:-"$ROOT/target/soak-artifacts"}

TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/nostrfy-soak.XXXXXX")
CONFIG="$TMPDIR/nostrfy.toml"
RELAY_PID=
TRAFFIC_PID=
START_TS=$(date +%s)
PHASE_START=$(date +%s)
CLEANED=0

fail() {
    echo "soak-chaos: FAIL: $*" >&2
    exit 1
}

now() {
    date +%s
}

require_int() {
    case "$2" in
        ''|*[!0-9]*) fail "$1 must be a non-negative integer (got '$2')" ;;
    esac
}

stop_relay() {
    if [ -n "$RELAY_PID" ]; then
        kill "$RELAY_PID" 2>/dev/null || true
        wait "$RELAY_PID" 2>/dev/null || true
        RELAY_PID=
    fi
}

stop_traffic() {
    if [ -n "$TRAFFIC_PID" ]; then
        kill "$TRAFFIC_PID" 2>/dev/null || true
        wait "$TRAFFIC_PID" 2>/dev/null || true
        TRAFFIC_PID=
    fi
}

cleanup() {
    if [ "$CLEANED" = "1" ]; then
        return 0
    fi
    CLEANED=1
    stop_traffic
    stop_relay
    if [ "${SOAK_KEEP_TMP:-0}" = "1" ]; then
        echo "soak-chaos: keeping temporary dir $TMPDIR (SOAK_KEEP_TMP=1)"
    else
        rm -rf "$TMPDIR"
    fi
    echo "soak-chaos: total elapsed $(( $(now) - START_TS ))s"
}
trap cleanup EXIT INT TERM

run_bench() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$BENCH_TIMEOUT_SECS" "$BENCH" "$@"
    else
        "$BENCH" "$@"
    fi
}

probe() {
    python3 "$PROBE" "$@"
}

start_relay() {
    echo "soak-chaos: starting relay on ws://127.0.0.1:$PORT (config $CONFIG)"
    "$BIN" --config "$CONFIG" start --foreground >>"$ARTIFACT_DIR/relay.log" 2>&1 &
    RELAY_PID=$!
    wait_ready
}

wait_ready() {
    i=0
    while [ "$i" -lt "$READY_TIMEOUT_SECS" ]; do
        if ! kill -0 "$RELAY_PID" 2>/dev/null; then
            tail -n 40 "$ARTIFACT_DIR/relay.log" >&2 || true
            fail "relay exited during startup (see $ARTIFACT_DIR/relay.log)"
        fi
        if probe health --http "$HTTP" --timeout 2 >/dev/null 2>&1; then
            echo "soak-chaos: relay ready after ${i}s"
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    tail -n 40 "$ARTIFACT_DIR/relay.log" >&2 || true
    fail "relay was not ready within ${READY_TIMEOUT_SECS}s"
}

# Refreshes $stats_accepted / $stats_duplicate from the live /relay/stats.
read_stats() {
    stats_out=$(probe stats --http "$HTTP" --timeout 5) \
        || fail "could not read /relay/stats"
    stats_accepted=$(printf '%s\n' "$stats_out" | sed -n 's/^accepted=\([0-9][0-9]*\) .*/\1/p')
    stats_duplicate=$(printf '%s\n' "$stats_out" | sed -n 's/.* duplicate=\([0-9][0-9]*\) .*/\1/p')
    [ -n "$stats_accepted" ] || fail "unparseable stats: $stats_out"
    [ -n "$stats_duplicate" ] || fail "unparseable stats: $stats_out"
}

phase_a() {
    PHASE_START=$(now)
    deadline=$(($(now) + SOAK_SECONDS))
    iterations=0
    while :; do
        iterations=$((iterations + 1))
        iter_start=$(now)
        echo "soak-chaos: [soak $iterations] ingest $INGEST_EVENTS"
        ingest_out=$(run_bench "$URL" ingest "$INGEST_EVENTS") \
            || fail "bench ingest failed"
        printf '%s\n' "$ingest_out"
        ingest_oks=$(printf '%s\n' "$ingest_out" | sed -n 's/.*(\([0-9][0-9]*\) ok, \([0-9][0-9]*\) accepted).*/\1/p' | head -n 1)
        ingest_accepted=$(printf '%s\n' "$ingest_out" | sed -n 's/.*(\([0-9][0-9]*\) ok, \([0-9][0-9]*\) accepted).*/\2/p' | head -n 1)
        [ "$ingest_oks" = "$INGEST_EVENTS" ] \
            || fail "ingest returned ${ingest_oks:-?}/${INGEST_EVENTS} OKs"
        [ "$ingest_accepted" = "$INGEST_EVENTS" ] \
            || fail "ingest accepted ${ingest_accepted:-?}/${INGEST_EVENTS} events"

        echo "soak-chaos: [soak $iterations] parallel-ingest ${PARALLEL_CONNS}x$PARALLEL_EVENTS"
        read_stats
        before_accepted=$stats_accepted
        before_duplicate=$stats_duplicate
        parallel_out=$(run_bench "$URL" parallel-ingest "$PARALLEL_CONNS" "$PARALLEL_EVENTS") \
            || fail "bench parallel-ingest failed"
        printf '%s\n' "$parallel_out"
        parallel_expected=$((PARALLEL_CONNS * PARALLEL_EVENTS))
        parallel_total=$(printf '%s\n' "$parallel_out" | sed -n 's/.* = \([0-9][0-9]*\) events in.*/\1/p' | head -n 1)
        [ "$parallel_total" = "$parallel_expected" ] \
            || fail "parallel-ingest reported ${parallel_total:-?}/${parallel_expected} events"
        read_stats
        accepted_delta=$((stats_accepted - before_accepted))
        duplicate_delta=$((stats_duplicate - before_duplicate))
        # A same-second replay can deduplicate an event; duplicates still
        # count as accepted by the relay's OK reply, so count both.
        [ $((accepted_delta + duplicate_delta)) -eq "$parallel_expected" ] \
            || fail "relay accounted ${accepted_delta} accepted + ${duplicate_delta} duplicate, expected ${parallel_expected}"

        echo "soak-chaos: [soak $iterations] fanout $FANOUT_SUBSCRIBERS subscribers x $FANOUT_PUBLISHES publishes"
        fanout_out=$(run_bench "$URL" fanout "$FANOUT_SUBSCRIBERS" "$FANOUT_PUBLISHES") \
            || fail "bench fanout failed"
        printf '%s\n' "$fanout_out"
        fanout_total=$((FANOUT_SUBSCRIBERS * FANOUT_PUBLISHES))
        fanout_delivered=$(printf '%s\n' "$fanout_out" | awk '/deliveries / { sub(/.*deliveries /, ""); print }')
        [ "$fanout_delivered" = "$fanout_total/$fanout_total" ] \
            || fail "fanout delivered ${fanout_delivered:-?}, expected $fanout_total/$fanout_total"

        echo "soak-chaos: [soak $iterations] iteration OK in $(( $(now) - iter_start ))s"
        [ "$(now)" -lt "$deadline" ] || break
    done
    echo "soak-chaos: phase A complete: $iterations iteration(s) in $(( $(now) - PHASE_START ))s"
}

# Verifies every acknowledged id from cycles 1..$1 against the restarted relay.
verify_acknowledged() {
    up_to=$1
    ids_file=
    verified=0
    vcycle=1
    while [ "$vcycle" -le "$up_to" ]; do
        ids_file="$TMPDIR/acked-$vcycle.txt"
        verify_out=$(probe verify --http "$HTTP" --ids-file "$ids_file" --timeout "$PROBE_TIMEOUT_SECS") \
            || fail "cycle $up_to: acknowledged events of cycle $vcycle are lost after restart"
        printf '%s\n' "$verify_out" >>"$ARTIFACT_DIR/probe.log"
        vcount=$(wc -l <"$ids_file" | tr -d ' ')
        verified=$((verified + vcount))
        vcycle=$((vcycle + 1))
    done
    echo "soak-chaos: verified $verified acknowledged event(s) from cycles 1..$up_to still queryable"
}

phase_b() {
    PHASE_START=$(now)
    cycle=1
    while [ "$cycle" -le "$CHAOS_CYCLES" ]; do
        cycle_start=$(now)
        ids_file="$TMPDIR/acked-$cycle.txt"
        echo "soak-chaos: [chaos $cycle/$CHAOS_CYCLES] publishing $CHAOS_EVENTS acknowledged events"
        publish_out=$(probe publish --url "$URL" --count "$CHAOS_EVENTS" \
            --prefix "soak-chaos-c$cycle-$(now)-$$" \
            --ids-file "$ids_file" --timeout "$PROBE_TIMEOUT_SECS") \
            || fail "chaos cycle $cycle: publishing acknowledged events failed"
        printf '%s\n' "$publish_out"
        printf '%s\n' "$publish_out" >>"$ARTIFACT_DIR/probe.log"

        # Fresh ingest traffic makes the SIGKILL land mid-write; the OKs
        # captured above are the durability contract being tested.
        "$BENCH" "$URL" ingest 100000000 >"$TMPDIR/traffic-$cycle.log" 2>&1 &
        TRAFFIC_PID=$!
        sleep "$CHAOS_TRAFFIC_SECS"
        echo "soak-chaos: [chaos $cycle] SIGKILL relay pid $RELAY_PID mid-traffic"
        kill -9 "$RELAY_PID" 2>/dev/null \
            || fail "chaos cycle $cycle: could not SIGKILL relay pid $RELAY_PID"
        wait "$RELAY_PID" 2>/dev/null || true
        RELAY_PID=
        stop_traffic

        start_relay
        probe health --http "$HTTP" --timeout 5 >/dev/null \
            || fail "chaos cycle $cycle: /health is not ok after restart"
        verify_acknowledged "$cycle"
        echo "soak-chaos: [chaos $cycle] recovered in $(( $(now) - cycle_start ))s"
        cycle=$((cycle + 1))
    done
    echo "soak-chaos: phase B complete: $CHAOS_CYCLES kill/restart cycle(s) in $(( $(now) - PHASE_START ))s"
}

main() {
    require_int SOAK_SECONDS "$SOAK_SECONDS"
    require_int CHAOS_CYCLES "$CHAOS_CYCLES"
    require_int CHAOS_EVENTS "$CHAOS_EVENTS"
    [ "$CHAOS_CYCLES" -ge 1 ] || fail "CHAOS_CYCLES must be at least 1"
    [ "$CHAOS_EVENTS" -ge 1 ] || fail "CHAOS_EVENTS must be at least 1"

    if [ -n "${SOAK_PORT:-}" ]; then
        PORT=$SOAK_PORT
    elif [ -n "${1:-}" ]; then
        PORT=$1
    elif [ -r /dev/urandom ]; then
        RAND=$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')
        PORT=$((20000 + RAND % 20000))
    else
        PORT=$((20000 + $$ % 20000))
    fi
    case "$PORT" in
        ''|*[!0-9]*) fail "invalid port: $PORT" ;;
    esac
    if ! { [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; }; then
        fail "port out of range: $PORT"
    fi
    URL="ws://127.0.0.1:$PORT"
    HTTP="http://127.0.0.1:$PORT"

    command -v python3 >/dev/null 2>&1 || fail "python3 is required for $PROBE"
    [ -f "$PROBE" ] || fail "missing probe client: $PROBE"

    mkdir -p "$ARTIFACT_DIR" "$TMPDIR/data" "$TMPDIR/images"
    : >"$ARTIFACT_DIR/relay.log"
    : >"$ARTIFACT_DIR/probe.log"

    selftest_out=$(probe selftest) || fail "soak_probe.py selftest failed"
    printf '%s\n' "$selftest_out"
    printf '%s\n' "$selftest_out" >>"$ARTIFACT_DIR/probe.log"

    echo "soak-chaos: building release binaries (nostrfy + bench)"
    cargo build --release --bins --examples --manifest-path "$ROOT/Cargo.toml"

    # The bench needs more than the default 64 connections for its 60
    # fan-out subscribers; the temp database and Blossom spool root keep
    # every write out of the repository (and the temp dir is removed).
    cat >"$CONFIG" <<EOF
[relay]
name = "soak-chaos"

[server]
host = "127.0.0.1"
port = $PORT
metrics_enabled = false

[limits]
max_connections_per_ip = 128

[database]
path = "$TMPDIR/data"

[blossom]
storage = "local"
local_path = "$TMPDIR/images"

[daemon]
pid_file = "$TMPDIR/nostrfy.pid"
log_file = "$TMPDIR/nostrfy.log"
stats_file = "$TMPDIR/nostrfy.stats.json"
EOF

    echo "soak-chaos: start: soak ${SOAK_SECONDS}s, ${CHAOS_CYCLES} chaos cycle(s), port $PORT"
    start_relay
    phase_a
    phase_b
    stop_relay
    echo "soak-chaos: PASS in $(( $(now) - START_TS ))s (relay log: $ARTIFACT_DIR/relay.log)"
}

main "$@"
