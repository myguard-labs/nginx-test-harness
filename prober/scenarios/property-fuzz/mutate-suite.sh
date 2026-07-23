#!/usr/bin/env bash
#
# The "suite" mutate.sh runs for the two property-fuzz mutation claims that
# live in driver.sh itself (PRNG determinism, replay). It is not a unit-test
# binary like http_test/rules_test -- it is the scenario, run exactly the way
# a human runs it from prober/ (see the local run recipe in this scenario's
# own memory/handoff notes and driver.sh's header). mutate.sh always executes
# suites relative to prober/, which is why this script assumes that cwd.
set -euo pipefail

cd "$(dirname "$0")/../.."

PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"

PROBER_ROOT="$(pwd)/.." \
PROBER_MODULE=ngx_http_test_ref_module.so \
PROBER_DIRECTIVE=test_ref_probe \
PROBER_PROBE="test_ref_probe;" \
PROBER_PORT="$PORT" \
./run-scenario.sh scenarios/property-fuzz nginx 1.29.0
