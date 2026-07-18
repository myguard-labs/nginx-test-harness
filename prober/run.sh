#!/usr/bin/env bash
#
# Boot a server with the probe-enabled module, run the prober rules against it,
# tear it down. Emits TAP on stdout, so `prove` consumes it like any other test.
#
#   prober/run.sh [flavor] [version]
#     flavor : nginx (default) | angie
#     version: source version; must match what the consumer's build fetched
#
# Module-agnostic: everything specific to the consuming module arrives through
# the environment, so this script is shared verbatim rather than forked per
# repo.
#
#   PROBER_ROOT      consumer repo root            (default: two levels up)
#   PROBER_BUILD     built source tree             (default: $ROOT/.build/<flavor>-<version>)
#   PROBER_MODULE    module .so basename           (required)
#   PROBER_DIRECTIVE directive proving the harness build (required)
#   PROBER_CONF      nginx.conf template with @LOAD@/@PORT@ (default: ./conf/prober.conf)
#   PROBER_RULES     rule glob                     (default: ./rules/*.rule)
#   PROBER_PORT      listen port                   (default: 18099)
#
# The build must have been made with the harness enabled, otherwise the probe
# directive does not exist and the config fails to load. run.sh checks for that
# up front rather than letting it surface as a confusing connect error.
set -euo pipefail

cd "$(dirname "$0")"

FLAVOR="${1:-nginx}"
VERSION="${2:-1.31.3}"
PORT="${PROBER_PORT:-18099}"

ROOT="${PROBER_ROOT:-$(cd ../.. && pwd)}"
BUILD="${PROBER_BUILD:-$ROOT/.build/${FLAVOR}-${VERSION}}"

# angie names its server binary objs/angie, nginx names it objs/nginx.
BIN="$BUILD/objs/nginx"
[ "$FLAVOR" = "angie" ] && BIN="$BUILD/objs/angie"

if [ -z "${PROBER_MODULE:-}" ] || [ -z "${PROBER_DIRECTIVE:-}" ]; then
    echo "Bail out! PROBER_MODULE and PROBER_DIRECTIVE must be set --" \
         "see the header of prober/run.sh"
    exit 1
fi

MODULE="$BUILD/objs/$PROBER_MODULE"
CONF="${PROBER_CONF:-./conf/prober.conf}"

if [ ! -x "$BIN" ]; then
    echo "Bail out! no server binary at $BIN --" \
         "build $FLAVOR $VERSION with the test harness enabled first"
    exit 1
fi

# debug/module modes build a dynamic .so and need load_module; asan and
# coverage modes use --add-module and link the module into the binary, where a
# load_module line fails with "module is already loaded".
#
# Decide by looking inside the BINARY, not by whether a .so exists: switching
# build modes leaves the previous mode's .so behind in objs/, so a file-exists
# test picks the stale artifact and emits load_module for a static build.
if grep -qa "$PROBER_DIRECTIVE" "$BIN"; then
    LOAD=""                                   # statically linked (asan/coverage)
elif [ -f "$MODULE" ] && grep -qa "$PROBER_DIRECTIVE" "$MODULE"; then
    LOAD="load_module $MODULE;"               # dynamic (debug/module)
else
    echo "Bail out! neither $BIN nor $MODULE carries $PROBER_DIRECTIVE --" \
         "rebuild with the test harness enabled"
    exit 1
fi

# nginx never frees its configuration pool, so LeakSanitizer reports the whole
# config parse as leaked on `nginx -t` and on every clean shutdown -- against an
# ASan build that turns the config test into a "Bail out!" before a single case
# runs. build-test.yml's ASan job disables leak detection for the same reason.
# Everything else ASan catches (use-after-free, overflow) stays on, which is the
# part worth having while the fault injector drives allocation-failure paths.
export ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:abort_on_error=1${ASAN_OPTIONS:+:$ASAN_OPTIONS}"

# glibc's own cheap heap checks, on every run that is NOT sanitized. They cost
# nothing and catch a class the suite otherwise cannot see: MALLOC_PERTURB_
# fills freshly-malloc'd bytes with a non-zero pattern and overwrites freed
# ones, so a module that reads uninitialised memory or touches a pointer after
# free gets a garbage value instead of the zeroes a quiet heap usually hands
# back -- which is why such bugs pass locally and fail in production.
#
# Sanitizer builds are excluded rather than merely redundant: ASan replaces the
# allocator, ignores these variables, and MALLOC_CHECK_'s abort path can fire
# inside ASan's own bookkeeping. Decided by looking for the ASan runtime in the
# binary, not by the static/dynamic distinction above -- the coverage build is
# also statically linked but is not sanitized, and would lose the check.
if ! grep -qa '__asan_\|__ubsan_' "$BIN"; then
    # 165 is arbitrary but deliberately odd and non-zero: as a pointer it is
    # unmapped, as a length it is implausible, as a byte it is not '\0'.
    export MALLOC_PERTURB_=165
    export MALLOC_CHECK_=3
fi

# The prober and json_test binaries are gitignored build products and run.sh
# does NOT build them. An edit to prober.c that was never compiled would
# otherwise be "verified" by the binary from before the edit: a green run that
# proves nothing about the change in hand. Same failure mode as a dead harness.
for ARTIFACT in ./prober ./json_test; do
    if [ -x "$ARTIFACT" ]; then
        STALE="$(find ./*.c ./*.h -newer "$ARTIFACT" 2>/dev/null || true)"

        if [ -n "$STALE" ]; then
            echo "Bail out! $ARTIFACT is older than its sources --" \
                 "run prober/build.sh:"
            printf '%s\n' "$STALE" | sed 's/^/# /'
            exit 1
        fi
    fi
done

# Check the oracle before trusting anything it says. Every rule assertion is
# evaluated against the JSON reader, so if that is broken the rules can all pass
# while proving nothing. Emitted as a bail-out rather than as extra TAP lines,
# so the plan the prober prints stays the plan the run reports.
if [ -x ./json_test ]; then
    if ! JSON_TEST_OUT="$(./json_test 2>&1)"; then
        echo "Bail out! prober JSON self-test failed:"
        printf '%s\n' "$JSON_TEST_OUT" | sed 's/^/# /'
        exit 1
    fi
else
    echo "Bail out! no json_test binary -- run prober/build.sh first"
    exit 1
fi

PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/prober.XXXXXX")"
trap 'rm -rf "$PREFIX"' EXIT

mkdir -p "$PREFIX/logs" "$PREFIX/conf"
sed -e "s#@LOAD@#$LOAD#" -e "s#@PORT@#$PORT#" \
    "$CONF" > "$PREFIX/conf/nginx.conf"

# The pid oracle compares the worker pid across each case and calls a change a
# crash. That inference only holds with ONE worker: with several, consecutive
# probe requests are answered by different live workers and every case fails on
# a server that is perfectly healthy. The conf comes from the consumer via
# PROBER_CONF, so this cannot be enforced by shipping a conf -- check the
# rendered file instead, and bail rather than emit a wall of false failures.
# Trailing space is stripped separately: "worker_processes 1 ;" is valid nginx,
# and an untrimmed "1 " would not equal "1" and would bail a healthy conf.
WORKERS="$(sed -n 's/^[[:space:]]*worker_processes[[:space:]]\+\([^;]*\);.*/\1/p' \
    "$PREFIX/conf/nginx.conf" | tail -n 1 | tr -d '[:space:]')"

if [ -n "$WORKERS" ] && [ "$WORKERS" != "1" ]; then
    echo "Bail out! worker_processes is \"$WORKERS\", but the pid oracle" \
         "requires exactly 1 -- with several workers a healthy server reports" \
         "a different pid per request and every case fails"
    exit 1
fi

if ! "$BIN" -t -p "$PREFIX" -c conf/nginx.conf >"$PREFIX/logs/conftest" 2>&1; then
    echo "Bail out! config test failed:"
    sed 's/^/# /' "$PREFIX/logs/conftest"
    exit 1
fi

"$BIN" -p "$PREFIX" -c conf/nginx.conf &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$PREFIX"' EXIT

# Wait for the listener rather than sleeping a fixed interval: a fixed sleep is
# either slow or flaky, and on a loaded CI box it is both.
for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
        break
    fi
    sleep 0.1
done

STATUS=0
# Unquoted on purpose: PROBER_RULES is a glob (and may name several files), and
# quoting it would pass the literal pattern to the prober as one filename.
# shellcheck disable=SC2086
./prober -H 127.0.0.1 -p "$PORT" ${PROBER_RULES:-rules/*.rule} || STATUS=$?

# Stop the server synchronously rather than leaving it to the EXIT trap. kill(1)
# only delivers TERM; without waiting for the process to actually go, the script
# can return while workers are still writing out their .gcda files, and the
# coverage job downstream then reads a partial profile. Waiting also means the
# error-log grep below reads a file nobody is still appending to.
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

# Surface what the HTTP responses cannot show. A worker that exits on a signal,
# finalizes a request twice or reuses a busy buffer logs at [alert] or [crit]
# and then carries on serving; the next request is answered by a respawned
# worker and every assertion in the run still passes. Without this the suite is
# green and the bug ships. It is a default, not an opt-in, because the failure
# mode it catches is precisely the one nobody thinks to enable a check for.
#
# [crit] is in the set deliberately: nginx logs slab exhaustion at [crit], which
# is the single most common real symptom of an unchecked shm allocation. Rules
# that provoke that ON PURPOSE -- a fault injector arming an allocation failure
# -- must therefore be able to exempt the line they expect, or the gate would
# fail every suite that tests its module's out-of-memory path. PROBER_ALLOW_LOG
# is that opt-out: an extended regex, matched per line, whose hits are reported
# but not fatal. Scoped to the pattern rather than a blanket off switch, so
# exempting "no memory" still leaves a segfault in the same run fatal.
LOG="$PREFIX/logs/error.log"

if [ -f "$LOG" ]; then
    SCRAPE="$(grep -E '\[(alert|crit|emerg)\]' "$LOG" || true)"

    if [ -n "${PROBER_ALLOW_LOG:-}" ] && [ -n "$SCRAPE" ]; then
        ALLOWED="$(printf '%s\n' "$SCRAPE" | grep -E "$PROBER_ALLOW_LOG" || true)"
        SCRAPE="$(printf '%s\n' "$SCRAPE" | grep -vE "$PROBER_ALLOW_LOG" || true)"

        if [ -n "$ALLOWED" ]; then
            echo "# error-log lines exempted by PROBER_ALLOW_LOG:"
            printf '%s\n' "$ALLOWED" | sed 's/^/# /'
        fi
    fi

    if [ -n "$SCRAPE" ]; then
        echo "# server logged alert/crit/emerg:"
        printf '%s\n' "$SCRAPE" | sed 's/^/# /'
        STATUS=1
    fi
fi

exit $STATUS
