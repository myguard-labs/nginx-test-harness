#!/usr/bin/env bash
#
# Build and run every TAP self-test in this directory.
#
# These tests need no server: they exercise the harness's own parsers and
# assertion evaluators as pure functions. That is deliberate -- the harness
# decides whether a module's test run is green, so a defect in the harness turns
# every rule that depends on it into a test that cannot fail, which is worse
# than a missing test because the run still reports success. Those defects have
# to be catchable without booting nginx, or CI will not catch them at all.
#
# run.sh runs this before it boots a server. CI runs it standalone, twice
# (plain and SAN=1).
set -euo pipefail

cd "$(dirname "$0")"

./build.sh >/dev/null

found=0
failed=0

for src in *_test.c; do
    [ -e "$src" ] || continue

    bin="./${src%.c}"
    found=$((found + 1))

    echo "# --- $bin"

    # Not `set -e`-fatal: one failing suite must not hide the ones after it,
    # and the aggregate exit status below is what the caller gates on.
    if ! "$bin"; then
        failed=$((failed + 1))
        echo "# $bin FAILED"
    fi
done

# Zero discovered suites is a failure, not a pass. A rename or a build-script
# regression that stops matching *_test.c would otherwise turn the whole
# self-test stage into a silent no-op that reports green.
if [ "$found" -eq 0 ]; then
    echo "# no *_test.c self-tests found -- refusing to report success" >&2
    exit 1
fi

if [ "$failed" -gt 0 ]; then
    echo "# $failed of $found self-test suites failed" >&2
    exit 1
fi

echo "# $found self-test suites passed"
