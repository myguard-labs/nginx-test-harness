#!/usr/bin/env bash
#
# TAP self-test for the backend-plumbing half of lib.sh.
#
# render_conf_test.sh covers the renderer; this file covers the functions a
# scenario uses to stand a fake upstream up, tear it down, and judge whether it
# misbehaved. They are shell, they touch real sockets and a real daemon, and
# nothing else in this repo executes them -- the same gap that let @PREFIX@ go
# unsubstituted for the whole life of the scenario tree.
#
# fakesrv itself is proven by backend_test.c and fakesrv_test.sh. What is under
# test here is the lifecycle around it: that a missing script is fatal, that a
# port is read only once it is real, and that a dead backend is reported rather
# than absorbed.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=33
tests_run=0
failures=0

echo "1..$PLANNED"

ok() {
    tests_run=$((tests_run + 1))
    if [ "$1" -eq 0 ]; then
        echo "ok $tests_run - $2"
    else
        failures=$((failures + 1))
        echo "not ok $tests_run - $2"
    fi
}

diag() { printf '# %s\n' "$1"; }

# shellcheck source=lib.sh
. ./lib.sh

if [ ! -x ./fakesrv ]; then
    echo "Bail out! no fakesrv binary -- run prober/build.sh first"
    exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lib_backend_test.XXXXXX")"

# ONE trap covering all three resources. A second `cleanup() { ... }` later in
# the file would silently REDEFINE this one rather than add to it, and whatever
# the first definition owned would leak on every run.
#
# Every command is guarded and the function ends in an explicit `return 0`. An
# EXIT trap's own status becomes the script's when it is the last thing to run,
# so a cleanup whose final command fails turns a fully passing suite red -- and
# it fails routinely here, because these tests kill the backend on purpose and
# `kill` on an already-reaped pid returns non-zero. This suite hit exactly that
# and reported exit 1 with every assertion green.
cleanup() {
    if [ -n "${PROBER_BACKEND_PID:-}" ]; then
        kill "$PROBER_BACKEND_PID" 2>/dev/null || true
    fi
    if [ -n "${LISTENER_PID:-}" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    if [ -n "${WORK:-}" ]; then
        rm -rf "$WORK" || true
    fi
    return 0
}
trap cleanup EXIT

# prober_backend_start writes into $PROBER_PREFIX, which the renderer normally
# creates. These tests do not render a conf, so stand one in directly.
PROBER_PREFIX="$WORK/prefix"
mkdir -p "$PROBER_PREFIX"

cat > "$WORK/ok.backend" <<'EOF'
proto   memcached
seed    hello  world
EOF

# A port nothing is listening on. Bound and released so the number is one the
# kernel just handed out, rather than a guess that some unrelated service on
# this host happens to be using -- which would turn the timeout assertions
# green for the wrong reason.
free_port() {
    local p
    p="$(python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()')"
    printf '%s' "$p"
}

# ---------------------------------------------------------------- wait_listen

DEAD_PORT="$(free_port)"

if prober_wait_listen 127.0.0.1 "$DEAD_PORT" 200; then
    ok 1 "a closed port times out"
else
    ok 0 "a closed port times out"
fi

# The timeout must actually bound the call. A loop that retries forever, or one
# whose step is much larger than advertised, still satisfies the assertion
# above by eventually returning 1 -- so the useful claim is that it returns
# WITHIN a sane multiple of what was asked. Measured with SECONDS, whose
# granularity is fine for a 4x-of-500ms ceiling and which needs no date(1).
start=$SECONDS
prober_wait_listen 127.0.0.1 "$DEAD_PORT" 500 || true
elapsed=$(( SECONDS - start ))

if [ "$elapsed" -le 2 ]; then
    ok 0 "the timeout bounds the call instead of hanging"
else
    diag "prober_wait_listen 500ms took ${elapsed}s"
    ok 1 "the timeout bounds the call instead of hanging"
fi

# A listening port must be seen. Backgrounded so the listener exists while the
# wait runs; `nc` is deliberately avoided here for the reason in the header, so
# the listener is python3's socket module, already required by free_port.
LISTEN_PORT="$(free_port)"
python3 -c "import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $LISTEN_PORT))
s.listen(8)
time.sleep(5)" &
LISTENER_PID=$!


if prober_wait_listen 127.0.0.1 "$LISTEN_PORT" 3000; then
    ok 0 "a listening port is detected"
else
    ok 1 "a listening port is detected"
fi

# A listener that is already up must be reported without spending the timeout.
# This is what makes the function usable in a boot path: a wait that always
# costs its full budget turns every scenario start into a fixed stall.
start=$SECONDS
prober_wait_listen 127.0.0.1 "$LISTEN_PORT" 3000
elapsed=$(( SECONDS - start ))

if [ "$elapsed" -le 1 ]; then
    ok 0 "an already-listening port returns promptly"
else
    diag "detecting a live listener took ${elapsed}s"
    ok 1 "an already-listening port returns promptly"
fi

# A timeout shorter than one sleep step must still attempt a connect. Rounding
# the iteration count down would make this report "not listening" for a port
# that is -- the failure would only appear in a caller that passed a small
# budget, which is exactly where a readiness check is tuned.
if prober_wait_listen 127.0.0.1 "$LISTEN_PORT" 1; then
    ok 0 "a sub-step timeout still attempts one connect"
else
    ok 1 "a sub-step timeout still attempts one connect"
fi

# ------------------------------------------------------------ backend lifecycle
#
# prober_backend_start depends on prober_wait_listen, asserted above. Checked
# again as a function rather than assumed, so a refactor that renames it fails
# here by name instead of surfacing as an obscure failure three checks later.
if declare -F prober_wait_listen >/dev/null; then
    ok 0 "prober_wait_listen is available to the backend lifecycle"
else
    ok 1 "prober_wait_listen is available to the backend lifecycle"
fi

# --------------------------------------------------------------------- start

prober_backend_start "$WORK/ok.backend"

case "${PROBER_BACKEND_PORT:-}" in
    ''|*[!0-9]*)
        diag "port was \"${PROBER_BACKEND_PORT:-}\""
        ok 1 "_start publishes a numeric port" ;;
    0)  diag "port was 0 -- the portfile was read before it was written"
        ok 1 "_start publishes a numeric port" ;;
    *)  ok 0 "_start publishes a numeric port" ;;
esac

# The port must be one a client can actually reach. A published number that
# nothing is listening on is the failure the readiness wait exists to prevent,
# and it would otherwise surface as a connect error inside the module under
# test -- pointing at the module rather than at the harness.
if (exec 3<>"/dev/tcp/127.0.0.1/$PROBER_BACKEND_PORT") 2>/dev/null; then
    ok 0 "the published port is actually accepting"
else
    ok 1 "the published port is actually accepting"
fi

if [ -n "${PROBER_BACKEND_PID:-}" ] && kill -0 "$PROBER_BACKEND_PID" 2>/dev/null; then
    ok 0 "_start leaves a live pid behind"
else
    ok 1 "_start leaves a live pid behind"
fi

# The journal is the instrument several planned scenarios assert against (the
# keepalive-reuse proof reads its accept count), so its path must be published
# and the file must exist once a command has been served.
printf 'get hello\r\n' > /dev/tcp/127.0.0.1/"$PROBER_BACKEND_PORT" 2>/dev/null || true

if [ -n "${PROBER_BACKEND_JOURNAL:-}" ] && [ -f "$PROBER_BACKEND_JOURNAL" ]; then
    ok 0 "_start publishes a journal path and the daemon writes it"
else
    diag "journal: ${PROBER_BACKEND_JOURNAL:-<unset>}"
    ok 1 "_start publishes a journal path and the daemon writes it"
fi

# The port must be read only from a NON-EMPTY portfile. Asserted as a property
# of the source, not by racing the window: fakesrv writes the file
# tmp+fsync+rename, so the interval in which a reader could see it empty is
# microseconds wide and its width is a property of the HOST -- a test that must
# catch it passes on one runner and fails on another. s69 hit exactly this on
# the daemon's own `portfile written non-atomically` mutant, where a shell loop
# watching for an existing-but-empty file never won the race on CI, and the
# resolution was the same: assert the mechanism.
#
# `-e` instead of `-s` is the defect this pins. It accepts the file the instant
# rename() makes it visible, and a reader that then parses "" as a port
# connects to port 0 -- the 1-in-20 flake fakesrv.c:37 exists to prevent.
# shellcheck disable=SC2016  # a literal grep pattern, not a shell expansion
if grep -q 'if \[ -s "\$portfile" \]' lib.sh; then
    ok 0 "_start waits for a non-empty portfile, not merely an existing one"
else
    diag "the portfile wait does not test for non-empty (-s)"
    ok 1 "_start waits for a non-empty portfile, not merely an existing one"
fi

# --------------------------------------------------------------------- scrape
#
# A healthy backend, still running, must produce no finding. Asserted before
# the failure cases so a scrape that reports a finding unconditionally cannot
# masquerade as working detection below.
if prober_backend_scrape >/dev/null 2>&1; then
    ok 0 "_scrape is silent on a healthy backend"
else
    diag "scrape reported: $(prober_backend_scrape 2>&1 || true)"
    ok 1 "_scrape is silent on a healthy backend"
fi

# ----------------------------------------------------------------------- stop

prober_backend_stop

if kill -0 "$PROBER_BACKEND_PID" 2>/dev/null; then
    ok 1 "_stop actually reaps the daemon"
else
    ok 0 "_stop actually reaps the daemon"
fi

# A second _stop must be a no-op. run-scenario.sh's teardown can reach it twice
# -- once on the normal path and once from a trap -- and a cleanup that fails
# on its second call turns a passing scenario red during teardown.
if prober_backend_stop; then
    ok 0 "_stop is idempotent"
else
    ok 1 "_stop is idempotent"
fi

# ------------------------------------------------- scrape: the died-backend case
#
# The pid is now dead, so the scrape must report it. This is the finding that
# matters most: a scenario whose upstream vanished mid-run sees only connection
# errors from the module under test, which reads as a module bug.
if prober_backend_scrape >/dev/null 2>&1; then
    ok 1 "_scrape reports a backend that died"
else
    ok 0 "_scrape reports a backend that died"
fi

if PROBER_BACKEND_ALLOW_EXIT=1 prober_backend_scrape >/dev/null 2>&1; then
    ok 0 "PROBER_BACKEND_ALLOW_EXIT exempts a deliberate kill"
else
    ok 1 "PROBER_BACKEND_ALLOW_EXIT exempts a deliberate kill"
fi

# The opt-out is scoped to the exit, not a blanket off switch: an exempted
# backend that ALSO wrote an error must still be a finding. Without this the
# variable would silence the parse-error path too, and a scenario that kills
# its backend on purpose would stop reporting a malformed script.
printf 'fakesrv: something went wrong\n' > "$PROBER_PREFIX/backend.err"

if PROBER_BACKEND_ALLOW_EXIT=1 prober_backend_scrape >/dev/null 2>&1; then
    ok 1 "ALLOW_EXIT still reports an errfile finding"
else
    ok 0 "ALLOW_EXIT still reports an errfile finding"
fi

rm -f "$PROBER_PREFIX/backend.err"

# ------------------------------------------------ start: the missing-script case
#
# THE mutation gate for P1-B. A nonexistent script must bail, never boot
# backendless: a scenario that silently runs with no upstream passes every
# assertion that does not need one, under a name claiming otherwise. Run in a
# subshell so the bail's `exit 1` cannot take this script down.
if ( prober_backend_start "$WORK/nonesuch.backend" ) >/dev/null 2>&1; then
    ok 1 "_start bails on a nonexistent script instead of booting backendless"
else
    ok 0 "_start bails on a nonexistent script instead of booting backendless"
fi

# The bail must name the MISSING SCRIPT, and that is not pedantry about wording
# -- it is what makes the assertion above non-vacuous. With the existence check
# deleted, _start still exits non-zero a few lines later: fakesrv cannot read
# the script, dies, and the "exited before publishing a port" bail fires. A
# check that only asks "did it fail" therefore passes with the guard REMOVED,
# proving nothing about the case it is named for. Verified by mutation: this is
# the assertion that goes red, the one above stays green.
MISSING_MSG="$( ( prober_backend_start "$WORK/nonesuch.backend" ) 2>&1 || true )"

case "$MISSING_MSG" in
    *"Bail out!"*"no backend script at"*)
        ok 0 "the bail names the missing script, not a downstream symptom" ;;
    *)  diag "bail message was: $MISSING_MSG"
        ok 1 "the bail names the missing script, not a downstream symptom" ;;
esac

# --- prober_cleanup (P1-B4) ------------------------------------------------
#
# The status-preservation cases come first because they are the reason this
# function is written the way it is: an EXIT trap's own status becomes the
# script's, so a cleanup that clobbers $? turns a failing scenario green with
# every assertion in the TAP stream still reading ok. Asserting merely that
# cleanup "runs" would not catch that -- the VALUE is the claim.
#
# Each case runs in a SUBSHELL that seeds $? and exits with what cleanup
# returned. A bare `( exit N )` in this file would trip `set -e` and kill the
# script mid-plan -- and a truncated TAP stream reads as "the rest passed",
# which is the trap lessons.md already records twice.
# The seeded status is the LAST thing before the call, with nothing in
# between to reset it.
# `set -e` stays ON inside here, deliberately. run-scenario.sh runs under
# `set -euo pipefail`, so that is the shell prober_cleanup must survive: an
# unguarded command in it aborts the trap partway and never reaches the
# `return "$rc"`. A helper that relaxed to `set +e` would absorb exactly that
# failure and report the mutant as caught while the assertion never ran --
# the vacuous-gate mode this file already documents twice.
#
# The seeded status has to reach prober_cleanup INTACT, and `set -e` would
# abort on the seed itself. An EXIT trap is the one construct that gives both:
# it is how the real caller invokes cleanup anyway, and `exit N` sets $? to N
# without `set -e` intervening. So this mirrors production exactly.
cleanup_rc() (
    set -eo pipefail
    PROBER_BACKEND_PID="${2:-}"
    PROBER_SERVER_PID="${3:-}"
    PROBER_PREFIX="${4:-}"
    trap 'prober_cleanup; exit $?' EXIT
    exit "$1"
)

CLEAN_RC=0; cleanup_rc 7 || CLEAN_RC=$?
if [ "$CLEAN_RC" -eq 7 ]; then
    ok 0 "cleanup preserves a non-zero \$? through to its own return"
else
    diag "cleanup returned $CLEAN_RC, seeded 7"
    ok 1 "cleanup preserves a non-zero \$? through to its own return"
fi

CLEAN_RC=0; cleanup_rc 0 || CLEAN_RC=$?
if [ "$CLEAN_RC" -eq 0 ]; then
    ok 0 "cleanup preserves a zero \$? rather than inventing a failure"
else
    diag "cleanup returned $CLEAN_RC, seeded 0"
    ok 1 "cleanup preserves a zero \$? rather than inventing a failure"
fi

# A stale pid is the exact input that made B3's unguarded kill flip the
# suite's exit status.
CLEAN_RC=0; cleanup_rc 3 999999 999999 "" || CLEAN_RC=$?
if [ "$CLEAN_RC" -eq 3 ]; then
    ok 0 "an already-dead pid does not change the status cleanup returns"
else
    diag "cleanup returned $CLEAN_RC, seeded 3"
    ok 1 "an already-dead pid does not change the status cleanup returns"
fi

CLEAN_PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/prober-cleanup.XXXXXX")"
PROBER_PREFIX="$CLEAN_PREFIX"
# Marked owned, as prober_make_prefix would: cleanup removes only what the
# harness created, so a hand-built prefix must claim ownership to stand in for
# a real one. The inherited (unowned) case is asserted separately below.
PROBER_PREFIX_OWNED=1
PROBER_BACKEND_PID=""
PROBER_SERVER_PID=""
prober_cleanup
if [ ! -d "$CLEAN_PREFIX" ]; then
    ok 0 "cleanup removes the prefix directory"
else
    ok 1 "cleanup removes the prefix directory"
fi

if [ -z "${PROBER_PREFIX:-}" ]; then
    ok 0 "cleanup clears the prefix handle so a second call cannot re-tear it"
else
    ok 1 "cleanup clears the prefix handle so a second call cannot re-tear it"
fi

# Idempotence is what lets the caller arm the trap before any resource exists
# and still run cleanup on the happy path.
CLEAN_RC=0; prober_cleanup || CLEAN_RC=$?
if [ "$CLEAN_RC" -eq 0 ]; then
    ok 0 "a second cleanup on cleared handles is a no-op, not an error"
else
    ok 1 "a second cleanup on cleared handles is a no-op, not an error"
fi

# --- prober_make_prefix (P1-B4) --------------------------------------------

PROBER_PREFIX=""
prober_make_prefix
MK_FIRST="$PROBER_PREFIX"
prober_make_prefix
if [ "$PROBER_PREFIX" = "$MK_FIRST" ] && [ -d "$MK_FIRST" ]; then
    ok 0 "make_prefix reuses an existing prefix instead of stranding it"
else
    ok 1 "make_prefix reuses an existing prefix instead of stranding it"
fi

# render_conf must accept the prefix the backend already populated, or the
# portfile and journal written into it would be orphaned by a second mktemp.
# The template is written here rather than reused from the tree: this repo
# ships no conf/ -- the template is consumer-supplied -- and prober_render_conf
# bails with `exit 1` on a missing one, which a sourced function's `|| true`
# cannot catch.
MK_TEMPLATE="$WORK/reuse.conf"
cat >"$MK_TEMPLATE" <<'CONF'
# listen @PORT@ in @PREFIX@, upstream @BACKEND_PORT@
CONF

PROBER_LOAD="" PROBER_RESOLVED_PORT=18099 PROBER_PROBE="" \
    prober_render_conf "$MK_TEMPLATE" >/dev/null 2>&1
if [ "$PROBER_PREFIX" = "$MK_FIRST" ]; then
    ok 0 "render_conf renders into the prefix make_prefix already created"
else
    diag "prefix moved: $MK_FIRST -> $PROBER_PREFIX"
    ok 1 "render_conf renders into the prefix make_prefix already created"
fi

rm -rf "$MK_FIRST"
PROBER_PREFIX=""

# --- prefix ownership (CodeRabbit #58, Major) -------------------------------
#
# PROBER_PREFIX can arrive from outside the harness: run-scenario.sh exports it
# to driver.sh, and a scenario's `env` file is sourced into the same shell. A
# cleanup that rm -rf's an inherited value destroys a directory the harness
# never created. Only a prefix we mktemp'd ourselves may be removed.

INHERITED="$(mktemp -d "${TMPDIR:-/tmp}/prober-inherited.XXXXXX")"
touch "$INHERITED/caller-data"

PROBER_PREFIX="$INHERITED"
PROBER_PREFIX_OWNED=""
PROBER_BACKEND_PID=""
PROBER_SERVER_PID=""
prober_cleanup

if [ -d "$INHERITED" ] && [ -f "$INHERITED/caller-data" ]; then
    ok 0 "cleanup does not delete a prefix the harness did not create"
else
    ok 1 "cleanup does not delete a prefix the harness did not create"
fi
rm -rf "$INHERITED"

# make_prefix must not claim ownership of a value it merely found.
PROBER_PREFIX="$INHERITED"
PROBER_PREFIX_OWNED=""
prober_make_prefix
if [ -z "${PROBER_PREFIX_OWNED:-}" ]; then
    ok 0 "make_prefix does not claim ownership of an inherited prefix"
else
    ok 1 "make_prefix does not claim ownership of an inherited prefix"
fi

PROBER_PREFIX=""
PROBER_PREFIX_OWNED=""
prober_make_prefix
OWNED_PREFIX="$PROBER_PREFIX"
if [ -n "${PROBER_PREFIX_OWNED:-}" ]; then
    ok 0 "make_prefix claims ownership of a prefix it created"
else
    ok 1 "make_prefix claims ownership of a prefix it created"
fi
prober_cleanup
rm -rf "$OWNED_PREFIX"

# --- scrape ordering (CodeRabbit #58, Major) --------------------------------
#
# prober_backend_scrape's liveness check asks whether the upstream survived the
# scenario -- its own message says "exited before teardown". Running it AFTER
# prober_backend_stop therefore sees the pid the stop just reaped and reports
# every backend scenario as failed. This asserts the ordering hazard directly,
# because no scenario in the tree ships a `backend` file yet and the
# integration path has no other coverage.

PROBER_PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/prober-order.XXXXXX")"
PROBER_PREFIX_OWNED=1
prober_backend_start "$WORK/ok.backend"

SCRAPE_LIVE=0
prober_backend_scrape >/dev/null 2>&1 || SCRAPE_LIVE=$?
if [ "$SCRAPE_LIVE" -eq 0 ]; then
    ok 0 "scrape is silent while the backend is still running (pre-teardown)"
else
    diag "scrape returned $SCRAPE_LIVE against a live backend"
    ok 1 "scrape is silent while the backend is still running (pre-teardown)"
fi

prober_backend_stop
SCRAPE_DEAD=0
prober_backend_scrape >/dev/null 2>&1 || SCRAPE_DEAD=$?
if [ "$SCRAPE_DEAD" -ne 0 ]; then
    ok 0 "scrape after stop reports the reaped pid -- why run-scenario.sh scrapes first"
else
    ok 1 "scrape after stop reports the reaped pid -- why run-scenario.sh scrapes first"
fi

prober_cleanup

# run-scenario.sh must call the scrape before the stop. Asserting the source
# because the ordering is the whole claim and a wrong order fails only on a
# scenario type that does not exist in this repo yet.
SCRAPE_LINE="$(grep -n 'prober_backend_scrape' run-scenario.sh | head -1 | cut -d: -f1)"
STOP_LINE="$(grep -n '^prober_backend_stop' run-scenario.sh | head -1 | cut -d: -f1)"
if [ -n "$SCRAPE_LINE" ] && [ -n "$STOP_LINE" ] && [ "$SCRAPE_LINE" -lt "$STOP_LINE" ]; then
    ok 0 "run-scenario.sh scrapes the backend before stopping it"
else
    diag "scrape at line ${SCRAPE_LINE:-none}, stop at line ${STOP_LINE:-none}"
    ok 1 "run-scenario.sh scrapes the backend before stopping it"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    diag "planned $PLANNED tests, ran $tests_run"
    exit 1
fi

[ "$failures" -eq 0 ]
