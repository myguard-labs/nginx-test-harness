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

    # Names the file from the moment it is about to be patched until it has
    # been put back, so the EXIT trap can restore it if this run is killed
    # in between. See summarise().
    MUT_ACTIVE="$file"

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
        MUT_ACTIVE=""
        broken=$((broken + 1))
        return
    fi

    # Failure mode 1: without this check a failed build silently re-runs the
    # previous binary, and its red result reads as a caught mutation.
    if ! ./build.sh >"$work/build.log" 2>&1; then
        echo "BROKEN  $name -- did not compile (see below); use x*0 rather than 0"
        sed -n '1,3p' "$work/build.log" | sed 's/^/          /'
        cp "$work/orig" "$file"
        MUT_ACTIVE=""
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
    MUT_ACTIVE=""
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

    #
    # Put the file back FIRST, before anything that could exit.
    #
    # Every restore in mutate() is a plain cp on a normal code path, so a run
    # killed mid-mutation -- a Ctrl-C, a harness timeout, an OOM -- leaves the
    # MUTATED SOURCE on disk. That is materially worse than the stale-binary
    # trap this script already documents: rebuilding does not clear it, and
    # `git status` reports only "modified", which is indistinguishable from the
    # feature work in progress around it. It happened for real: a foreground
    # timeout killed a full run and left `opt_check = 0` in prober.c, silently
    # disabling --check, and the four build configs that ran afterwards all
    # reported green against mutated source.
    #
    # MUT_ACTIVE is set immediately before the patch is applied and cleared
    # immediately after the restore, so it names a file only while one is
    # genuinely mutated.
    #
    if [ -n "${MUT_ACTIVE:-}" ] && [ -f "$work/orig" ]; then
        cp "$work/orig" "$MUT_ACTIVE"
        echo "restored $MUT_ACTIVE (run interrupted mid-mutation)"
    fi

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

trap summarise EXIT INT TERM


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

# ---- transport: hold --------------------------------------------------------

# The wait is the directive. Zeroed, the connection is written and closed
# immediately, which still delivers the request and still ends with a FIN --
# every assertion but the timing one passes.
mutate "hold: wait zeroed" http.c \
    '        sleep_ms(hold_ms);' '        sleep_ms(hold_ms * 0);' http_test

# A hold that resets is an abort wearing a different name, and the FIN-not-RST
# assertion is the only thing standing between the two.
mutate "hold: ends with a reset instead of a FIN" http.c \
    '    if (hold_ms != HTTP_HOLD_NONE) {
        sleep_ms(hold_ms);' \
    '    if (hold_ms != HTTP_HOLD_NONE) {
        struct linger lg2; lg2.l_onoff = 1; lg2.l_linger = 0;
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg2, sizeof(lg2));
        sleep_ms(hold_ms);' http_test

mutate "hold: response-expectation guard removed" rules.c \
    'if (tc->saw_hold && tc->n_expects > 0) {' 'if (0) {' rules_test

mutate "hold: ceiling not counted toward the stall budget" rules.c \
    '        total += tc->hold_ms;' '        total += tc->hold_ms * 0;' rules_test

# ---- expect_close_within ----------------------------------------------------

# The opt-in itself. Ignoring want_close puts the read timeout back to being a
# transport error, so a close-deadline case would abort with "request failed"
# instead of failing on the assertion that asked the question -- a server defect
# reported as a harness fault.
# Neutering this one takes care. `if (0)` leaves want_close unused and trips
# -Werror=unused-parameter; `if (want_close * 0)` then trips
# -Werror=int-in-bool-context. Both are failure mode 1 from this script's
# header, hit for real on two successive drafts. `< 0` keeps the parameter used
# AND the expression boolean, while never being true for any value the callers
# pass (0 or 1).
mutate "close_within: want_close ignored" http.c \
    '                if (want_close) {' '                if (want_close < 0) {' http_test

# The comparison itself, in both directions. `>=` passes a close that missed the
# deadline by exactly nothing; inverting it fails every prompt close.
mutate "close_within: deadline comparison inverted" assert.c \
    '        if (resp->close_ms > deadline_ms) {' \
    '        if (resp->close_ms < deadline_ms) {' assert_test

# A timeout judged as a pass is the whole failure this directive exists to
# prevent: the server never closed, and the case reports green.
#
# The mutation returns 1 rather than re-labelling the case. An earlier version
# changed `case HTTP_CLOSE_TIMEOUT:` to `case 999:`, which SURVIVED for an
# uninteresting reason: the label fell through to `default:`, which also fails,
# so the mutant behaved identically to the original. An equivalent mutant is not
# a coverage gap, and reading it as one sends you looking for a missing test
# that does not exist -- so the mutation targets the verdict itself.
mutate "close_within: timeout treated as a pass" assert.c \
    '    case HTTP_CLOSE_TIMEOUT:
        snprintf(why, whylen,
                 "connection still open %ld ms after the request; wanted a "
                 "close within %ld ms", resp->close_ms, deadline_ms);
        return 0;' \
    '    case HTTP_CLOSE_TIMEOUT:
        snprintf(why, whylen,
                 "connection still open %ld ms after the request; wanted a "
                 "close within %ld ms", resp->close_ms, deadline_ms);
        return 1;' assert_test

# "No close observed" must fail rather than pass. If the default branch returns
# 1, a case whose exchange never read the socket asserts nothing and says ok.
mutate "close_within: unobserved close treated as a pass" assert.c \
    '        snprintf(why, whylen,
                 "no connection close was observed, so a %ld ms close "
                 "deadline cannot be judged", deadline_ms);
        return 0;' \
    '        snprintf(why, whylen,
                 "no connection close was observed, so a %ld ms close "
                 "deadline cannot be judged", deadline_ms);
        return 1;' assert_test

# NOT MUTATED: the errno discrimination in the read loop's error branch
# (`errno == ECONNRESET ? RESET : NONE`).
#
# Widening it back to "every error is a reset" cannot be caught by an honest
# test, so no mutation is listed for it. On a connected loopback socket the only
# errno a fixture can actually provoke there is ECONNRESET; the branch exists for
# EBADF/ENOTCONN, which cannot be produced without corrupting the fd behind
# http_request()'s back. A test that reached them would be testing its own
# sabotage rather than the transport.
#
# Listed here rather than omitted silently: the next person to audit coverage
# will notice the gap, and the useful thing to know is that it was measured and
# judged unreachable, not overlooked. The discrimination is still worth having --
# it decides the text a rule author reads when a close deadline fails.

# The measurement, not just the verdict. A close_ms stuck at zero passes every
# deadline no matter how long the server actually took.
mutate "close_within: FIN time not measured" http.c \
    '        if (n == 0) {
            resp->close_reason = HTTP_CLOSE_FIN;
            resp->close_ms = elapsed_since(sent_at);' \
    '        if (n == 0) {
            resp->close_reason = HTTP_CLOSE_FIN;
            resp->close_ms = elapsed_since(sent_at) * 0;' http_test

# The ceiling. A deadline past the read timeout can never be missed, so without
# this bound the directive accepts values at which it cannot go red.
mutate "close_within: ceiling removed" rules.c \
    '            if (ms < 0 || ms > MAX_CLOSE_WITHIN_MS) {' \
    '            if (ms < 0) {' rules_test

# The guards against the two directives that never read the socket. Without
# them a case can ask for a deadline nothing will ever measure.
mutate "close_within: abort exclusion removed" rules.c \
    '            if (tc->saw_abort) {
                die("%s:%d: abort and expect_close_within are mutually "' \
    '            if (0) {
                die("%s:%d: abort and expect_close_within are mutually "' \
    rules_test

# The slot reset. Without it a second load into the same array inherits the
# previous file'"'"'s saw_ flags and dies on a duplicate its own text never had.
mutate "close_within: case slot not reset between loads" rules.c \
    '            case_free(&cases[n - 1]);' \
    '            if (0) case_free(&cases[n - 1]);' rules_test

# The runtime half of the close-deadline ceiling. rules.c caps the directive at
# a compile-time constant; only prober.c can compare it against -t. Without this
# guard a deadline past the timeout parses fine and can never fail, which is the
# un-reddable gate the constant ceiling exists to prevent -- reached by the one
# path that ceiling cannot cover. (Found by CodeRabbit on PR #39.)
mutate "close_within: deadline-past-timeout guard removed" prober.c \
    '        if (cases[c].saw_close_within
            && cases[c].close_within_ms >= opt_timeout_ms)' \
    '        if (cases[c].saw_close_within
            && cases[c].close_within_ms >= opt_timeout_ms * 1000000)' \
    check_test.sh

# ---- CLI --------------------------------------------------------------------

# The flag not taking effect is the failure that matters: --check would fall
# through to the request loop and try to connect, which against a host with no
# server reads as "the rule file is bad" rather than as a broken flag.
mutate "--check: flag does not take effect" prober.c \
    '            opt_check = 1;' '            opt_check = 0;' check_test.sh
