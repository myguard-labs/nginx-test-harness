#!/usr/bin/env bash
#
# TAP self-test for the backend-plumbing half of lib.sh.
#
# render_conf_test.sh covers the renderer; this file covers the functions a
# scenario uses to stand a fake upstream up and wait for it. They are shell,
# they touch real sockets, and nothing else in the repo executes them -- the
# same gap that let @PREFIX@ go unsubstituted for the whole life of the
# scenario tree.
#
# The listener under test is a plain bash-side socket, not fakesrv: this file
# asserts the WAIT, and borrowing the daemon would make a red result ambiguous
# between the two.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=5
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

cleanup() {
    kill "$LISTENER_PID" 2>/dev/null || true
    wait "$LISTENER_PID" 2>/dev/null || true
    return 0
}
trap cleanup EXIT

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

if [ "$tests_run" -ne "$PLANNED" ]; then
    diag "planned $PLANNED tests, ran $tests_run"
    exit 1
fi

[ "$failures" -eq 0 ]
