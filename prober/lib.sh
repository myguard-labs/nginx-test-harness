#!/usr/bin/env bash
#
# Shared engine for run.sh and run-scenario.sh: everything involved in booting
# a probe-enabled server, gating the run on things that would otherwise produce
# a green run that proves nothing, and tearing the server down again.
#
# This file is sourced, not executed. Functions communicate through the
# PROBER_* variables they set (documented per function) rather than through
# stdout, so callers can compose them without command substitution eating the
# TAP stream.
#
# Callers must run under `set -euo pipefail`; this file assumes it and does not
# re-assert it, because re-running `set -u` here would mask a caller that
# forgot it only until the first unset variable inside a function.

# prober_resolve FLAVOR VERSION
#
# Sets: PROBER_FLAVOR PROBER_VERSION PROBER_RESOLVED_ROOT PROBER_RESOLVED_BUILD
#       PROBER_SERVER_BIN PROBER_MODULE_PATH PROBER_RESOLVED_PORT
#
# Everything specific to the consuming module arrives through the environment,
# so these scripts are shared verbatim rather than forked per repo.
prober_resolve() {
    PROBER_FLAVOR="${1:-nginx}"
    PROBER_VERSION="${2:-1.31.3}"
    PROBER_RESOLVED_PORT="${PROBER_PORT:-18099}"

    PROBER_RESOLVED_ROOT="${PROBER_ROOT:-$(cd ../.. && pwd)}"
    PROBER_RESOLVED_BUILD="${PROBER_BUILD:-$PROBER_RESOLVED_ROOT/.build/${PROBER_FLAVOR}-${PROBER_VERSION}}"

    # angie names its server binary objs/angie, nginx names it objs/nginx.
    PROBER_SERVER_BIN="$PROBER_RESOLVED_BUILD/objs/nginx"
    [ "$PROBER_FLAVOR" = "angie" ] && PROBER_SERVER_BIN="$PROBER_RESOLVED_BUILD/objs/angie"

    if [ -z "${PROBER_MODULE:-}" ] || [ -z "${PROBER_DIRECTIVE:-}" ]; then
        echo "Bail out! PROBER_MODULE and PROBER_DIRECTIVE must be set --" \
             "see the header of prober/run.sh"
        exit 1
    fi

    PROBER_MODULE_PATH="$PROBER_RESOLVED_BUILD/objs/$PROBER_MODULE"

    if [ ! -x "$PROBER_SERVER_BIN" ]; then
        echo "Bail out! no server binary at $PROBER_SERVER_BIN --" \
             "build $PROBER_FLAVOR $PROBER_VERSION with the test harness enabled first"
        exit 1
    fi
}

# prober_detect_load
#
# Sets: PROBER_LOAD -- the load_module line for the conf template, or empty.
#
# debug/module modes build a dynamic .so and need load_module; asan and
# coverage modes use --add-module and link the module into the binary, where a
# load_module line fails with "module is already loaded".
#
# Decide by looking inside the BINARY, not by whether a .so exists: switching
# build modes leaves the previous mode's .so behind in objs/, so a file-exists
# test picks the stale artifact and emits load_module for a static build.
prober_detect_load() {
    if grep -qa "$PROBER_DIRECTIVE" "$PROBER_SERVER_BIN"; then
        PROBER_LOAD=""                            # statically linked (asan/coverage)
    elif [ -f "$PROBER_MODULE_PATH" ] && grep -qa "$PROBER_DIRECTIVE" "$PROBER_MODULE_PATH"; then
        PROBER_LOAD="load_module $PROBER_MODULE_PATH;"   # dynamic (debug/module)
    else
        echo "Bail out! neither $PROBER_SERVER_BIN nor $PROBER_MODULE_PATH carries" \
             "$PROBER_DIRECTIVE -- rebuild with the test harness enabled"
        exit 1
    fi
}

# prober_heap_env
#
# Exports ASAN_OPTIONS always, MALLOC_PERTURB_/MALLOC_CHECK_ on unsanitized
# builds.
#
# nginx never frees its configuration pool, so LeakSanitizer reports the whole
# config parse as leaked on `nginx -t` and on every clean shutdown -- against an
# ASan build that turns the config test into a "Bail out!" before a single case
# runs. Everything else ASan catches (use-after-free, overflow) stays on.
#
# MALLOC_PERTURB_/MALLOC_CHECK_ are glibc's own cheap heap checks, on every run
# that is NOT sanitized. They catch a class the suite otherwise cannot see:
# uninitialised reads and use-after-free get a garbage value instead of the
# zeroes a quiet heap usually hands back. Sanitizer builds are excluded rather
# than merely redundant: ASan replaces the allocator, ignores these variables,
# and MALLOC_CHECK_'s abort path can fire inside ASan's own bookkeeping.
# Decided by looking for the ASan runtime in the binary, not by the
# static/dynamic distinction -- the coverage build is also statically linked
# but is not sanitized, and would lose the check.
prober_heap_env() {
    export ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:abort_on_error=1${ASAN_OPTIONS:+:$ASAN_OPTIONS}"

    if ! grep -qa '__asan_\|__ubsan_' "$PROBER_SERVER_BIN"; then
        # 165 is arbitrary but deliberately odd and non-zero: as a pointer it
        # is unmapped, as a length it is implausible, as a byte it is not '\0'.
        export MALLOC_PERTURB_=165
        export MALLOC_CHECK_=3
    fi
}

# prober_gates
#
# The prober and json_test binaries are gitignored build products and this
# engine does NOT build them. An edit to prober.c that was never compiled would
# otherwise be "verified" by the binary from before the edit: a green run that
# proves nothing about the change in hand. Same failure mode as a dead harness.
#
# Then check the oracle before trusting anything it says: every rule assertion
# is evaluated against the JSON reader, so if that is broken the rules can all
# pass while proving nothing. Emitted as a bail-out rather than as extra TAP
# lines, so the plan the prober prints stays the plan the run reports.
#
# Expects to be called with CWD = the prober/ directory.
prober_gates() {
    local artifact stale json_out

    # fakesrv is checked alongside the prober because a scenario's verdict
    # depends on the fake upstream behaving as its script says. A stale one
    # would be trusted forever: the faults a rebuilt script asks for would
    # silently not happen, and the scenario would pass by testing the happy
    # path under a name claiming otherwise.
    for artifact in ./prober ./json_test ./fakesrv; do
        if [ -x "$artifact" ]; then
            stale="$(find ./*.c ./*.h -newer "$artifact" 2>/dev/null || true)"

            if [ -n "$stale" ]; then
                echo "Bail out! $artifact is older than its sources --" \
                     "run prober/build.sh:"
                printf '%s\n' "$stale" | sed 's/^/# /'
                exit 1
            fi
        fi
    done

    if [ -x ./json_test ]; then
        if ! json_out="$(./json_test 2>&1)"; then
            echo "Bail out! prober JSON self-test failed:"
            printf '%s\n' "$json_out" | sed 's/^/# /'
            exit 1
        fi
    else
        echo "Bail out! no json_test binary -- run prober/build.sh first"
        exit 1
    fi
}

# prober_render_conf TEMPLATE
#
# Sets: PROBER_PREFIX -- fresh server prefix (mktemp), conf rendered into it.
# The caller owns cleanup of $PROBER_PREFIX (run.sh and run-scenario.sh both
# install traps; a library installing its own trap would silently overwrite
# the caller's).
prober_render_conf() {
    local template="$1"

    if [ ! -f "$template" ]; then
        echo "Bail out! no conf template at $template -- a scenario needs its" \
             "own nginx.conf or a PROBER_CONF default"
        exit 1
    fi

    PROBER_PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/prober.XXXXXX")"
    mkdir -p "$PROBER_PREFIX/logs" "$PROBER_PREFIX/conf"

    # @PREFIX@ resolves to the per-run temp prefix created just above. A
    # scenario conf needs it for pid/error_log/access_log paths: nginx resolves
    # a relative path against its compiled-in prefix, not against the rendered
    # conf, so an unsubstituted or relative path lands outside the sandbox --
    # or, as with a literal "@PREFIX@", fails open() and kills the config test.
    #
    # @PROBE@ and @PROBE_ZONE@ are the consumer's, because the probe directive
    # is module-specific: shield's is `shield_probe probezone;` and it needs a
    # `shield_ban_zone probezone:1m;` at http level to name that zone. A generic
    # scenario tree cannot hardcode either, so the consumer supplies them and
    # the scenarios only say WHERE they go. Empty is legitimate -- a module
    # whose probe needs no zone leaves PROBER_PROBE_ZONE unset.
    #
    # @BACKEND_PORT@ is the port a fake upstream bound, published by
    # prober_backend_start. It renders EMPTY when PROBER_BACKEND_PORT is unset,
    # and that is deliberate: a scenario with no backend is the normal case --
    # every scenario checked in today has none. Do NOT give this placeholder
    # @PROBE@'s bail-if-unset rule. @PROBE@ bails because an empty probe
    # location falls through to `location /` and the prober misreads that
    # handler's body as the probe document; an empty upstream port has no
    # equivalent silent-misdirection path, it simply fails nginx's config test
    # where the operator can read it.
    #
    # A conf that asks for @PROBE@ while the consumer supplied nothing must
    # bail, not render empty: an empty probe location falls through to
    # `location /`, the prober parses that handler's body as the probe document
    # and reports "malformed number". That misdirection is exactly the bug this
    # placeholder pair exists to end, so it fails loudly at render instead.
    if grep -q '@PROBE@' "$template" && [ -z "${PROBER_PROBE:-}" ]; then
        echo "Bail out! $template uses @PROBE@ but PROBER_PROBE is unset --" \
             "the consumer must supply its probe directive (e.g." \
             "PROBER_PROBE='shield_probe probezone;')"
        exit 1
    fi

    # Every value is escaped before it reaches sed's replacement side, where
    # `&` means "the whole matched text", `\` starts an escape and `#` closes
    # the s### expression. Unescaped, a probe directive containing `&` renders
    # the placeholder back into the output -- @PROBE@ would reach nginx as a
    # literal, which is the silent-failure mode this placeholder pair exists to
    # end. `#` is worse only in being loud. These are consumer-supplied values,
    # so the harness cannot assume they are tame.
    sed_repl() { printf '%s' "$1" | sed -e 's#[\\&/]#\\&#g' -e 's#\##\\\##g'; }

    sed -e "s#@LOAD@#$(sed_repl "$PROBER_LOAD")#" \
        -e "s#@PORT@#$(sed_repl "$PROBER_RESOLVED_PORT")#" \
        -e "s#@PREFIX@#$(sed_repl "$PROBER_PREFIX")#" \
        -e "s#@PROBE@#$(sed_repl "${PROBER_PROBE:-}")#" \
        -e "s#@PROBE_ZONE@#$(sed_repl "${PROBER_PROBE_ZONE:-}")#" \
        -e "s#@BACKEND_PORT@#$(sed_repl "${PROBER_BACKEND_PORT:-}")#" \
        "$template" > "$PROBER_PREFIX/conf/nginx.conf"
}

# prober_check_conf
#
# Two rendered-conf gates, each guarding an inference the engine relies on.
#
# The pid oracle compares the worker pid across each case and calls a change a
# crash. That inference only holds with ONE worker: with several, consecutive
# probe requests are answered by different live workers and every case fails on
# a server that is perfectly healthy. The conf comes from the consumer, so this
# cannot be enforced by shipping a conf -- check the rendered file instead, and
# bail rather than emit a wall of false failures. Trailing space is stripped
# separately: "worker_processes 1 ;" is valid nginx, and an untrimmed "1 "
# would not equal "1" and would bail a healthy conf.
#
# `daemon off;` is required because the engine backgrounds the binary itself
# and keeps $! as the master pid for teardown and for scenario drivers that
# send it signals. With daemon mode on, $! is a launcher that exits
# immediately: teardown kills nothing, the orphaned server keeps the port, and
# every later scenario fails on bind -- a confusing distance from the cause.
prober_check_conf() {
    local workers

    workers="$(sed -n 's/^[[:space:]]*worker_processes[[:space:]]\+\([^;]*\);.*/\1/p' \
        "$PROBER_PREFIX/conf/nginx.conf" | tail -n 1 | tr -d '[:space:]')"

    if [ -n "$workers" ] && [ "$workers" != "1" ]; then
        echo "Bail out! worker_processes is \"$workers\", but the pid oracle" \
             "requires exactly 1 -- with several workers a healthy server reports" \
             "a different pid per request and every case fails"
        exit 1
    fi

    if ! grep -qE '^[[:space:]]*daemon[[:space:]]+off[[:space:]]*;' \
        "$PROBER_PREFIX/conf/nginx.conf"; then
        echo "Bail out! conf lacks \"daemon off;\" -- the engine tracks the" \
             "master by \$! and a daemonized server orphans itself past teardown"
        exit 1
    fi
}

# prober_boot
#
# Sets: PROBER_SERVER_PID. Config-tests first so a broken conf is a bail-out
# with the actual error, not a connect timeout.
prober_boot() {
    if ! "$PROBER_SERVER_BIN" -t -p "$PROBER_PREFIX" -c conf/nginx.conf \
        >"$PROBER_PREFIX/logs/conftest" 2>&1; then
        echo "Bail out! config test failed:"
        sed 's/^/# /' "$PROBER_PREFIX/logs/conftest"
        exit 1
    fi

    "$PROBER_SERVER_BIN" -p "$PROBER_PREFIX" -c conf/nginx.conf &
    PROBER_SERVER_PID=$!

    # Wait for the listener rather than sleeping a fixed interval: a fixed
    # sleep is either slow or flaky, and on a loaded CI box it is both. Verify
    # after each connect that the server is still alive: a stale listener on the
    # port can answer TCP connects while our server exited on bind() failure.
    local _i
    for _i in $(seq 1 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$PROBER_RESOLVED_PORT") 2>/dev/null; then
            if kill -0 "$PROBER_SERVER_PID" 2>/dev/null; then
                break
            fi
            # Server is dead but listener answered. Stale listener; retry.
        fi
        sleep 0.1
    done

    # Final check: server must still be alive.
    if ! kill -0 "$PROBER_SERVER_PID" 2>/dev/null; then
        echo "Bail out! server failed to start (pid $PROBER_SERVER_PID exited):"
        if [ -f "$PROBER_PREFIX/logs/error.log" ]; then
            sed 's/^/# /' "$PROBER_PREFIX/logs/error.log"
        fi
        exit 1
    fi
}

# prober_stop
#
# Stop the server synchronously rather than leaving it to an EXIT trap. kill(1)
# only delivers TERM; without waiting for the process to actually go, the
# script can return while workers are still writing out their .gcda files, and
# the coverage job downstream then reads a partial profile. Waiting also means
# the error-log scrape reads a file nobody is still appending to.
prober_stop() {
    kill "$PROBER_SERVER_PID" 2>/dev/null || true
    wait "$PROBER_SERVER_PID" 2>/dev/null || true
}

# prober_scrape_log
#
# Returns 1 if the error log holds an unexempted alert/crit/emerg line.
#
# Surfaces what the HTTP responses cannot show. A worker that exits on a
# signal, finalizes a request twice or reuses a busy buffer logs at [alert] or
# [crit] and then carries on serving; the next request is answered by a
# respawned worker and every assertion in the run still passes. Without this
# the suite is green and the bug ships. It is a default, not an opt-in, because
# the failure mode it catches is precisely the one nobody thinks to enable a
# check for.
#
# [crit] is in the set deliberately: nginx logs slab exhaustion at [crit],
# which is the single most common real symptom of an unchecked shm allocation.
# Rules that provoke that ON PURPOSE -- a fault injector arming an allocation
# failure -- must therefore be able to exempt the line they expect, or the gate
# would fail every suite that tests its module's out-of-memory path.
# PROBER_ALLOW_LOG is that opt-out: an extended regex, matched per line, whose
# hits are reported but not fatal. Scoped to the pattern rather than a blanket
# off switch, so exempting "no memory" still leaves a segfault in the same run
# fatal.
prober_scrape_log() {
    local log="$PROBER_PREFIX/logs/error.log" scrape allowed

    [ -f "$log" ] || return 0

    scrape="$(grep -E '\[(alert|crit|emerg)\]' "$log" || true)"

    if [ -n "${PROBER_ALLOW_LOG:-}" ] && [ -n "$scrape" ]; then
        allowed="$(printf '%s\n' "$scrape" | grep -E "$PROBER_ALLOW_LOG" || true)"
        scrape="$(printf '%s\n' "$scrape" | grep -vE "$PROBER_ALLOW_LOG" || true)"

        if [ -n "$allowed" ]; then
            echo "# error-log lines exempted by PROBER_ALLOW_LOG:"
            printf '%s\n' "$allowed" | sed 's/^/# /'
        fi
    fi

    if [ -n "$scrape" ]; then
        echo "# server logged alert/crit/emerg:"
        printf '%s\n' "$scrape" | sed 's/^/# /'
        return 1
    fi

    return 0
}
