#!/usr/bin/env bash
#
# TAP self-test for `prober --check`.
#
# The rule parser itself is covered by rules_test.c. What that cannot reach is
# the CLI wiring: that --check actually routes into load_rules(), that it exits
# on the parse verdict rather than the run's, and -- the load-bearing property
# -- that it never opens a connection. A --check that quietly fell through to
# the request loop would hang or fail against a host with no server on it, and
# a --check that skipped the parser would report every rule file as valid.
#
# No server is booted, which is the point: every case here must pass with
# nothing listening on the prober's default port.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=7
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

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

./build.sh >/dev/null

# ---- a valid rule file ------------------------------------------------------

cat >"$WORK/good.rule" <<'EOF'
name    a well-formed case
from    127.0.0.1
send    GET / HTTP/1.1\r\n
send    Host: prober\r\nConnection: close\r\n\r\n
expect  status=200
EOF

# Nothing is listening on the default port. A --check that reached the request
# loop would fail or block here, so a clean exit is itself the evidence that it
# did not connect.
out="$(./prober --check "$WORK/good.rule" 2>&1)" && status=0 || status=$?
ok "$status" "--check exits 0 on a valid rule file with no server running"

case "$out" in
    *"1 cases parsed"*) ok 0 "--check reports the parsed case count" ;;
    *) ok 1 "--check reports the parsed case count (got: $out)" ;;
esac

case "$out" in
    *"1.."*) ok 1 "--check emits no TAP plan (got: $out)" ;;
    *) ok 0 "--check emits no TAP plan" ;;
esac

# ---- malformed input --------------------------------------------------------

cat >"$WORK/unknown.rule" <<'EOF'
name    a case with a bogus directive
frobnicate 1
EOF

./prober --check "$WORK/unknown.rule" >/dev/null 2>&1 && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" "--check exits nonzero on an unknown directive"

# A cross-directive guard, not a syntax error: every line parses, but the case
# asserts on a response that a reset connection will never produce. This is the
# class of defect --check exists to catch before a run burns a server boot.
cat >"$WORK/semantic.rule" <<'EOF'
name    abort with a response assertion
from    127.0.0.1
send    GET / HTTP/1.1\r\n
abort   5
expect_not body~oops
EOF

out="$(./prober --check "$WORK/semantic.rule" 2>&1)" && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" "--check rejects abort carrying a response expectation"

case "$out" in
    *"no response to assert on"*)
        ok 0 "--check explains why the abort case was rejected" ;;
    *)
        ok 1 "--check explains why the abort case was rejected (got: $out)" ;;
esac

./prober --check "$WORK/does-not-exist.rule" >/dev/null 2>&1 && status=0 || status=$?
ok "$((status == 0 ? 1 : 0))" "--check exits nonzero on an unopenable rule file"

# ---- plan reconciliation ----------------------------------------------------

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
    echo "# $failures of $tests_run self-tests failed" >&2
    exit 1
fi
