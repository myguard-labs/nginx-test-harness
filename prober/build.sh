#!/usr/bin/env bash
#
# Build the rule-driven prober and every TAP self-test beside it. Strict by
# default: this is test infrastructure, and a harness that compiles with
# warnings is a harness nobody trusts.
set -euo pipefail

cd "$(dirname "$0")"

CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O1 -g -std=c11 -Wall -Wextra -Werror -Wshadow -Wpointer-arith}"

# SAN=1 builds the prober itself under ASan/UBSan. The prober parses attacker-
# shaped text from rule files and untrusted-shaped bytes off the socket, so it
# gets the same treatment the module under test does.
if [ "${SAN:-0}" = "1" ]; then
    CFLAGS="$CFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"
    # UBSan defaults to printing and continuing, which would let a signed
    # overflow or a bad shift scroll past in a run that still exits 0.
    export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"
fi

# Every translation unit except the one holding main(). Test binaries link the
# whole set rather than a hand-maintained per-test list, so adding a module does
# not mean editing N link lines -- and a test that reaches into another unit
# keeps working instead of failing at link time for a bookkeeping reason.
LIB="json.c http.c util.c rules.c assert.c"

# shellcheck disable=SC2086
$CC $CFLAGS -o prober prober.c $LIB

built="$PWD/prober"

# Self-tests are discovered, not listed: dropping a new *_test.c in this
# directory is enough to get it built and (via test.sh) run. A test that has to
# be registered in two places is a test that eventually is not run at all.
for src in *_test.c; do
    [ -e "$src" ] || continue

    bin="${src%.c}"

    # shellcheck disable=SC2086
    $CC $CFLAGS -o "$bin" "$src" $LIB

    built="$built $PWD/$bin"
done

echo "built: $built"
