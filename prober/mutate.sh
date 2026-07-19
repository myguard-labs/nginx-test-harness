#!/usr/bin/env bash
#
# Mutation smoke test: break the code on purpose, and require the suite to
# notice.
#
# WHY THIS EXISTS. This repo's self-tests decide whether a module's run is
# green, so a test that cannot fail is worse than a missing one -- the run still
# reports success. A passing suite proves the tests RAN; only a failing one
# proves they ASSERT. Every directive added here has been mutation-checked by
# hand, and that ritual has caught a real defect on each of the last three
# passes -- including one (a dropped SO_LINGER) where the feature's entire
# effect was untested behind assertions that looked thorough.
#
# Doing it by hand is where the danger is. Three separate failure modes have
# each produced a result that READ like "the mutation was caught" when nothing
# of the sort happened:
#
#   1. The mutation did not compile. The build fails, the STALE binary from the
#      last build runs, the suite goes red -- indistinguishable from a caught
#      mutation unless the build's exit status is checked. The -Werror wall
#      makes this common: zeroing a parameter's only use trips
#      -Werror=unused-parameter, so `x * 0` is the safe form, not `0`.
#   2. The edit did not apply. A sed expression that silently matches nothing
#      leaves the code pristine; the suite passes; that reads as SURVIVED and
#      sends you hunting a coverage gap that does not exist.
#   3. The wrong suite was run. A transport mutation checked against the parser
#      tests survives trivially, because those tests never touch the transport.
#
# So this script verifies, for every mutation: that the patch changed the file,
# that the build succeeded, and that the named suite -- not merely some suite --
# went red. Anything else is reported as a BROKEN mutation, never as a result.
#
# Usage:  ./mutate.sh            run every mutation
#         ./mutate.sh SO_LINGER  run those whose name matches a substring
#
# Exit status is 0 only when every mutation was caught.
set -uo pipefail

cd "$(dirname "$0")" || exit 1

FILTER="${1:-}"

work=$(mktemp -d)

pass=0
fail=0
broken=0

#
# One mutation: name, file, python replacement (old -> new), suite that must
# catch it.
#
# The edit is a literal string replacement rather than a regex: a sed pattern
# that fails to match is silent, and failure mode 2 above is exactly that. A
# literal old-string either appears or does not, and this checks which.
#
mutate () {
    local name="$1" file="$2" old="$3" new="$4" suite="$5"

    if [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]]; then
        return
    fi

    cp "$file" "$work/orig"

    if ! MUT_FILE="$file" MUT_OLD="$old" MUT_NEW="$new" python3 - <<'PY'
import os, sys
path, old, new = os.environ['MUT_FILE'], os.environ['MUT_OLD'], os.environ['MUT_NEW']
s = open(path).read()
if s.count(old) != 1:
    sys.exit(f"anchor appears {s.count(old)} times, need exactly 1")
open(path, 'w').write(s.replace(old, new))
PY
    then
        echo "BROKEN  $name -- anchor did not match uniquely (mutation not applied)"
        cp "$work/orig" "$file"
        broken=$((broken + 1))
        return
    fi

    # Failure mode 1: without this check a failed build silently re-runs the
    # previous binary, and its red result reads as a caught mutation.
    if ! ./build.sh >"$work/build.log" 2>&1; then
        echo "BROKEN  $name -- did not compile (see below); use x*0 rather than 0"
        sed -n '1,3p' "$work/build.log" | sed 's/^/          /'
        cp "$work/orig" "$file"
        broken=$((broken + 1))
        return
    fi

    # Failure mode 3: the NAMED suite must go red. A mutation that only breaks
    # some other suite is not evidence that this one asserts anything.
    if ./"$suite" >/dev/null 2>&1; then
        echo "SURVIVED $name -- $suite still passes; the behaviour is untested"
        fail=$((fail + 1))
    else
        echo "caught   $name ($suite)"
        pass=$((pass + 1))
    fi

    cp "$work/orig" "$file"
}


#
# The summary and the exit decision live in a trap rather than at the end of the
# file, so a mutation appended below this point still counts. Written flat, an
# added mutation lands AFTER the tally and is silently excluded from it -- the
# script would report "survived 0" while printing a SURVIVED line, and exit 0.
# That was not hypothetical: it happened while self-testing this script.
#
summarise () {
    local rc=0

    echo
    echo "caught $pass, survived $fail, broken $broken"

    # A broken mutation is a failure of THIS SCRIPT, not a verdict about the
    # code, and must never be reported as either a pass or a coverage gap.
    if [ "$fail" -gt 0 ] || [ "$broken" -gt 0 ]; then
        rc=1
    fi

    rm -rf "$work"
    exit "$rc"
}

trap summarise EXIT


# ---- transport: send-side pacing -------------------------------------------

mutate "send_slow: inter-chunk sleep zeroed" http.c \
    'if (off < len) {
            sleep_ms(ms);
        }' 'if (off < len) {
            sleep_ms(ms * 0);
        }' http_test

mutate "send_slow: leading stall dropped" http.c \
    'sleep_ms(pauses[i].ms);

            if (write_paced(' 'sleep_ms(pauses[i].ms * 0);

            if (write_paced(' http_test

mutate "send_slow: chunk ignored" http.c \
    'if (n > chunk) {
            n = chunk;
        }' 'if (0) {
            n = chunk;
        }' http_test

# ---- transport: shutdown ----------------------------------------------------

mutate "shutdown: call skipped" http.c \
    '(void) shutdown(fd, shut_how);' \
    '(void) shut_how;' http_test

# ---- transport: abort -------------------------------------------------------

mutate "abort: SO_LINGER disabled" http.c \
    'lg.l_onoff = 1;' 'lg.l_onoff = 0;' http_test

mutate "abort: offset ignored" http.c \
    'abort_at < req_len ? abort_at : req_len' 'req_len' http_test

# ---- transport: receive-side pacing ----------------------------------------

mutate "recv_slow: pacing sleep zeroed" http.c \
    'sleep_ms(recv_opt->ms);' 'sleep_ms(recv_opt->ms * 0);' http_test

mutate "recv_slow: chunk cap ignored" http.c \
    'if (want > recv_opt->chunk) {
                want = recv_opt->chunk;
            }' 'if (0) {
                want = recv_opt->chunk;
            }' http_test

mutate "recv_slow: sleeps before the EOF read" http.c \
    'if (paced_full) {' 'if (paced_full || 1) {' http_test

mutate "so_rcvbuf: setsockopt dropped" http.c \
    'if (recv_opt != NULL && recv_opt->rcvbuf > 0) {' \
    'if (0) {' http_test

# ---- parser: zero-value sentinels ------------------------------------------
#
# Both of these are the trap the sentinels exist to prevent: a zeroed field
# silently applying the directive to every case in the file.

mutate "shutdown: default becomes SHUT_RD" rules.c \
    'cases[n - 1].shut_how = HTTP_SHUT_NONE;' \
    'cases[n - 1].shut_how = 0;' rules_test

mutate "abort: default becomes offset 0" rules.c \
    'cases[n - 1].abort_at = HTTP_ABORT_NONE;' \
    'cases[n - 1].abort_at = 0;' rules_test

# ---- parser: guards ---------------------------------------------------------

mutate "abort: response-expectation guard removed" rules.c \
    'if (tc->saw_abort && tc->n_expects > 0) {' 'if (0) {' rules_test

mutate "send_slow: post-parse ceiling not enforced" rules.c \
    'if (total > MAX_PAUSE_MS) {
                die("%s: case \"%s\" stalls %ld ms in total, over the %d ms "' \
    'if (0) {
                die("%s: case \"%s\" stalls %ld ms in total, over the %d ms "' \
    rules_test
