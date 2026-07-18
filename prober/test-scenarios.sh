#!/usr/bin/env bash
#
# Run every scenario and aggregate to one TAP stream, so `prove` consumes the
# whole scenario tree as a single test file.
#
#   prober/test-scenarios.sh [flavor] [version]
#
#   PROBER_SCENARIOS  glob of scenario directories
#                     (default: ./scenarios/*/ relative to this directory;
#                     consumers pass an absolute glob, same as PROBER_RULES)
#
# One TAP test per scenario: the scenario's own TAP output (run-scenario.sh)
# is indented as a TAP-13 subtest block, then summarized as ok / not ok. A
# scenario whose requires gate declined is reported as an explicit SKIP --
# visible in the output, not silently absent, because a scenario that stops
# running on every box is a hole in coverage someone has to notice.
set -euo pipefail

cd "$(dirname "$0")"

FLAVOR="${1:-nginx}"
VERSION="${2:-1.31.3}"

GLOB="${PROBER_SCENARIOS:-./scenarios/*/}"

# Zero discovered scenarios is a failure, not a pass -- a typo'd glob would
# otherwise turn the whole stage into a silent no-op that reports green. Same
# rule test.sh applies to *_test.c discovery, for the same reason.
# shellcheck disable=SC2086
if ! compgen -G $GLOB >/dev/null; then
    echo "Bail out! no scenarios match $GLOB"
    exit 1
fi

SCENARIOS=()
# shellcheck disable=SC2086
for DIR in $GLOB; do
    [ -d "$DIR" ] && SCENARIOS+=("${DIR%/}")
done

echo "1..${#SCENARIOS[@]}"

N=0
STATUS=0

for DIR in "${SCENARIOS[@]}"; do
    N=$((N + 1))
    NAME="$(basename "$DIR")"

    # Not `set -e`-fatal: one failing scenario must not hide the ones after
    # it, and the aggregate exit status below is what CI gates on.
    OUT=""
    RC=0
    OUT="$(./run-scenario.sh "$DIR" "$FLAVOR" "$VERSION" 2>&1)" || RC=$?

    printf '%s\n' "$OUT" | sed 's/^/    /'

    if [ $RC -eq 0 ]; then
        case "$OUT" in
            "1..0 # SKIP"*)
                # Propagate the skip and its reason to the aggregate line, so
                # a `prove` summary shows WHICH scenarios did not run here.
                echo "ok $N - $NAME # SKIP ${OUT#1..0 # SKIP }" ;;
            *)
                echo "ok $N - $NAME" ;;
        esac
    else
        echo "not ok $N - $NAME"
        STATUS=1
    fi
done

exit $STATUS
