#!/usr/bin/env bash
#
# Run ONE scenario: boot a fresh probe-enabled server under the scenario's
# environment, run its driver or its rules, tear down, scrape the log.
#
#   prober/run-scenario.sh <scenario-dir> [flavor] [version]
#     flavor : nginx (default) | angie
#     version: source version; must match what the consumer's build fetched
#
# A scenario is a directory. Every file in it is optional except the rules --
# and even those may be omitted when a driver.sh is present, because a pure
# orchestration scenario asserts through its driver:
#
#   nginx.conf   conf template with @LOAD@/@PORT@ (default: $PROBER_CONF)
#   *.rule       rule files for the prober         (default: $PROBER_RULES)
#   env          sourced before boot: LD_PRELOAD, ulimit, PROBER_ALLOW_LOG,
#                PROBER_PORT overrides -- anything the scenario needs armed
#                before the master process forks
#   driver.sh    replaces the plain prober invocation (Layer 3): interleaves
#                prober runs with signals to the master, asserts pidfile
#                state, and emits the scenario's TAP itself
#   requires     executable gate; nonzero exit means the scenario is SKIPPED
#                (TAP skip-all), not failed -- missing tool, missing kernel
#                feature, missing locale are environment facts, not bugs
#
# Driver contract (exported before driver.sh runs):
#   PROBER_CLIENT      absolute path to the prober binary
#   PROBER_LIB         absolute path to lib.sh (source it for prober_stop etc.)
#   PROBER_SCENARIO    absolute path to the scenario directory
#   PROBER_PREFIX      server prefix; logs at $PROBER_PREFIX/logs/error.log,
#                      pidfile wherever the conf template put it
#   PROBER_SERVER_BIN  server binary (for USR2 binary-upgrade scenarios)
#   PROBER_SERVER_PID  master pid ($!): HUP/USR2/TERM target
#   PROBER_RESOLVED_PORT  the listen port
#
# The driver's stdout IS the scenario's TAP; its exit status is the scenario's
# verdict, combined with the error-log scrape exactly as a rules run is.
set -euo pipefail

cd "$(dirname "$0")"

SCENARIO="${1:?usage: run-scenario.sh <scenario-dir> [flavor] [version]}"
SCENARIO="$(cd "$SCENARIO" && pwd)"

# shellcheck source=lib.sh
. ./lib.sh

# The requires gate runs before anything expensive and before the env file, so
# a skip costs nothing and cannot be corrupted by a half-applied environment.
# Skip-all is the whole point: an unmet requirement on this box is not a red.
if [ -x "$SCENARIO/requires" ]; then
    if ! REASON="$("$SCENARIO/requires" 2>&1)"; then
        echo "1..0 # SKIP ${REASON:-$SCENARIO/requires gate not met}"
        exit 0
    fi
fi

prober_resolve "${2:-nginx}" "${3:-1.31.3}"
prober_detect_load
prober_heap_env
prober_gates

# The env file is sourced, not executed, so ulimit and export take effect in
# THIS shell -- the one about to fork the server. That is the mechanism by
# which a scenario arms LD_PRELOAD (mockeagain), lowers `ulimit -n`
# (fd-starve), or sets PROBER_ALLOW_LOG for a fault it provokes on purpose.
# It runs after prober_resolve so it may override the resolved port, and
# before conf render so template substitution sees the final values.
if [ -f "$SCENARIO/env" ]; then
    # shellcheck source=/dev/null
    . "$SCENARIO/env"
    PROBER_RESOLVED_PORT="${PROBER_PORT:-$PROBER_RESOLVED_PORT}"
fi

CONF="$SCENARIO/nginx.conf"
[ -f "$CONF" ] || CONF="${PROBER_CONF:-./conf/prober.conf}"

prober_render_conf "$CONF"
trap 'rm -rf "$PROBER_PREFIX"' EXIT
prober_check_conf
prober_boot
trap 'prober_stop; rm -rf "$PROBER_PREFIX"' EXIT

STATUS=0

if [ -x "$SCENARIO/driver.sh" ]; then
    export PROBER_CLIENT="$PWD/prober"
    export PROBER_LIB="$PWD/lib.sh"
    export PROBER_SCENARIO="$SCENARIO"
    export PROBER_PREFIX PROBER_SERVER_BIN PROBER_SERVER_PID PROBER_RESOLVED_PORT

    "$SCENARIO/driver.sh" || STATUS=$?
else
    # A scenario without rules and without a driver can assert nothing; that
    # is a broken scenario, not an empty test plan, and reporting it as green
    # would be the vacuous-gate failure mode this repo keeps re-learning.
    # Deliberately a literal glob string, expanded unquoted at the prober call
    # below -- identical treatment to PROBER_RULES.
    RULES="$SCENARIO/*.rule"
    if ! compgen -G "$RULES" >/dev/null; then
        RULES="${PROBER_RULES:-rules/*.rule}"
        if ! compgen -G "$RULES" >/dev/null; then
            echo "Bail out! scenario $SCENARIO has no driver.sh, no *.rule," \
                 "and no PROBER_RULES fallback -- nothing to assert"
            exit 1
        fi
    fi

    # Same export as run.sh's: the per-case no_error_log / grep_error_log
    # directives slice this file by offset around each case.
    export PROBER_ERROR_LOG="$PROBER_PREFIX/logs/error.log"

    # Unquoted on purpose: RULES is a glob (and may name several files), and
    # quoting it would pass the literal pattern to the prober as one filename.
    # shellcheck disable=SC2086
    ./prober -H 127.0.0.1 -p "$PROBER_RESOLVED_PORT" $RULES || STATUS=$?
fi

prober_stop
trap 'rm -rf "$PROBER_PREFIX"' EXIT

prober_scrape_log || STATUS=1

exit $STATUS
