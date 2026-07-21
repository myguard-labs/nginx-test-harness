#!/usr/bin/env bash
#
# Shared engine for run.sh and run-scenario.sh: everything involved in booting
# a probe-enabled server, gating the run on things that would otherwise produce
# a green run that proves nothing, and tearing the server down again.
#
# This file is sourced, not executed. Functions communicate through the
# PROBER_* variables they set (documented per function) rather than through
# stdout, so callers can compose them without command substitution eating the
# TAP stream.
#
# Callers must run under `set -euo pipefail`; this file assumes it and does not
# re-assert it, because re-running `set -u` here would mask a caller that
# forgot it only until the first unset variable inside a function.

# prober_resolve FLAVOR VERSION
#
# Sets: PROBER_FLAVOR PROBER_VERSION PROBER_RESOLVED_ROOT PROBER_RESOLVED_BUILD
#       PROBER_SERVER_BIN PROBER_MODULE_PATH PROBER_RESOLVED_PORT
#
# Everything specific to the consuming module arrives through the environment,
# so these scripts are shared verbatim rather than forked per repo.
prober_resolve() {
    PROBER_FLAVOR="${1:-nginx}"
    PROBER_VERSION="${2:-1.31.3}"
    PROBER_RESOLVED_PORT="${PROBER_PORT:-18099}"

    PROBER_RESOLVED_ROOT="${PROBER_ROOT:-$(cd ../.. && pwd)}"
    PROBER_RESOLVED_BUILD="${PROBER_BUILD:-$PROBER_RESOLVED_ROOT/.build/${PROBER_FLAVOR}-${PROBER_VERSION}}"

    # angie names its server binary objs/angie, nginx names it objs/nginx.
    PROBER_SERVER_BIN="$PROBER_RESOLVED_BUILD/objs/nginx"
    [ "$PROBER_FLAVOR" = "angie" ] && PROBER_SERVER_BIN="$PROBER_RESOLVED_BUILD/objs/angie"

    if [ -z "${PROBER_MODULE:-}" ] || [ -z "${PROBER_DIRECTIVE:-}" ]; then
        echo "Bail out! PROBER_MODULE and PROBER_DIRECTIVE must be set --" \
             "see the header of prober/run.sh"
        exit 1
    fi

    PROBER_MODULE_PATH="$PROBER_RESOLVED_BUILD/objs/$PROBER_MODULE"

    if [ ! -x "$PROBER_SERVER_BIN" ]; then
        echo "Bail out! no server binary at $PROBER_SERVER_BIN --" \
             "build $PROBER_FLAVOR $PROBER_VERSION with the test harness enabled first"
        exit 1
    fi
}

# prober_detect_load
#
# Sets: PROBER_LOAD -- the load_module line for the conf template, or empty.
#
# debug/module modes build a dynamic .so and need load_module; asan and
# coverage modes use --add-module and link the module into the binary, where a
# load_module line fails with "module is already loaded".
#
# Decide by looking inside the BINARY, not by whether a .so exists: switching
# build modes leaves the previous mode's .so behind in objs/, so a file-exists
# test picks the stale artifact and emits load_module for a static build.
prober_detect_load() {
    if grep -qa "$PROBER_DIRECTIVE" "$PROBER_SERVER_BIN"; then
        PROBER_LOAD=""                            # statically linked (asan/coverage)
    elif [ -f "$PROBER_MODULE_PATH" ] && grep -qa "$PROBER_DIRECTIVE" "$PROBER_MODULE_PATH"; then
        PROBER_LOAD="load_module $PROBER_MODULE_PATH;"   # dynamic (debug/module)
    else
        echo "Bail out! neither $PROBER_SERVER_BIN nor $PROBER_MODULE_PATH carries" \
             "$PROBER_DIRECTIVE -- rebuild with the test harness enabled"
        exit 1
    fi
}

# prober_heap_env
#
# Exports ASAN_OPTIONS always, MALLOC_PERTURB_/MALLOC_CHECK_ on unsanitized
# builds.
#
# nginx never frees its configuration pool, so LeakSanitizer reports the whole
# config parse as leaked on `nginx -t` and on every clean shutdown -- against an
# ASan build that turns the config test into a "Bail out!" before a single case
# runs. Everything else ASan catches (use-after-free, overflow) stays on.
#
# MALLOC_PERTURB_/MALLOC_CHECK_ are glibc's own cheap heap checks, on every run
# that is NOT sanitized. They catch a class the suite otherwise cannot see:
# uninitialised reads and use-after-free get a garbage value instead of the
# zeroes a quiet heap usually hands back. Sanitizer builds are excluded rather
# than merely redundant: ASan replaces the allocator, ignores these variables,
# and MALLOC_CHECK_'s abort path can fire inside ASan's own bookkeeping.
# Decided by looking for the ASan runtime in the binary, not by the
# static/dynamic distinction -- the coverage build is also statically linked
# but is not sanitized, and would lose the check.
prober_heap_env() {
    export ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:abort_on_error=1${ASAN_OPTIONS:+:$ASAN_OPTIONS}"

    if ! grep -qa '__asan_\|__ubsan_' "$PROBER_SERVER_BIN"; then
        # 165 is arbitrary but deliberately odd and non-zero: as a pointer it
        # is unmapped, as a length it is implausible, as a byte it is not '\0'.
        export MALLOC_PERTURB_=165
        export MALLOC_CHECK_=3
    fi
}

# prober_gates
#
# The prober and json_test binaries are gitignored build products and this
# engine does NOT build them. An edit to prober.c that was never compiled would
# otherwise be "verified" by the binary from before the edit: a green run that
# proves nothing about the change in hand. Same failure mode as a dead harness.
#
# Then check the oracle before trusting anything it says: every rule assertion
# is evaluated against the JSON reader, so if that is broken the rules can all
# pass while proving nothing. Emitted as a bail-out rather than as extra TAP
# lines, so the plan the prober prints stays the plan the run reports.
#
# Expects to be called with CWD = the prober/ directory.
prober_gates() {
    local artifact stale json_out

    # fakesrv is checked alongside the prober because a scenario's verdict
    # depends on the fake upstream behaving as its script says. A stale one
    # would be trusted forever: the faults a rebuilt script asks for would
    # silently not happen, and the scenario would pass by testing the happy
    # path under a name claiming otherwise.
    for artifact in ./prober ./json_test ./fakesrv; do
        if [ -x "$artifact" ]; then
            stale="$(find ./*.c ./*.h -newer "$artifact" 2>/dev/null || true)"

            if [ -n "$stale" ]; then
                echo "Bail out! $artifact is older than its sources --" \
                     "run prober/build.sh:"
                printf '%s\n' "$stale" | sed 's/^/# /'
                exit 1
            fi
        fi
    done

    if [ -x ./json_test ]; then
        if ! json_out="$(./json_test 2>&1)"; then
            echo "Bail out! prober JSON self-test failed:"
            printf '%s\n' "$json_out" | sed 's/^/# /'
            exit 1
        fi
    else
        echo "Bail out! no json_test binary -- run prober/build.sh first"
        exit 1
    fi
}

# prober_make_prefix
#
# Sets: PROBER_PREFIX -- fresh server prefix (mktemp), unless one already
# exists, in which case this is a no-op and the existing prefix is kept.
#
# Split out of prober_render_conf because the fake upstream needs the prefix
# BEFORE the conf is rendered: prober_backend_start writes its portfile,
# journal and errfile there, and the conf cannot be rendered until the backend
# has published the port that @BACKEND_PORT@ substitutes. Callers with no
# backend need not call this at all -- prober_render_conf still creates the
# prefix itself, so run.sh is unaffected.
#
# Reusing an existing prefix rather than replacing it is what makes the two
# call sites compose: a second call would otherwise strand the first prefix,
# leaking it past a cleanup that only knows the newer path.
prober_make_prefix() {
    [ -z "${PROBER_PREFIX:-}" ] || return 0

    PROBER_PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/prober.XXXXXX")"
    mkdir -p "$PROBER_PREFIX/logs" "$PROBER_PREFIX/conf"

    # Ownership is recorded at creation, and ONLY here. prober_cleanup does an
    # `rm -rf` on the prefix, and the value can arrive from outside the
    # harness: run-scenario.sh exports PROBER_PREFIX to driver.sh, and a
    # scenario's `env` file is sourced into the same shell, so either can set
    # it to a directory the harness did not create and does not own. Deleting
    # that would be the harness destroying a caller's data on a normal exit.
    # A prefix we did not mktemp is used but never removed.
    PROBER_PREFIX_OWNED=1
}

# prober_render_conf TEMPLATE
#
# Sets: PROBER_PREFIX -- fresh server prefix (mktemp), conf rendered into it.
# The caller owns cleanup of $PROBER_PREFIX (run.sh and run-scenario.sh both
# install traps; a library installing its own trap would silently overwrite
# the caller's).
prober_render_conf() {
    local template="$1"

    if [ ! -f "$template" ]; then
        echo "Bail out! no conf template at $template -- a scenario needs its" \
             "own nginx.conf or a PROBER_CONF default"
        exit 1
    fi

    prober_make_prefix

    # @PREFIX@ resolves to the per-run temp prefix created just above. A
    # scenario conf needs it for pid/error_log/access_log paths: nginx resolves
    # a relative path against its compiled-in prefix, not against the rendered
    # conf, so an unsubstituted or relative path lands outside the sandbox --
    # or, as with a literal "@PREFIX@", fails open() and kills the config test.
    #
    # @PROBE@ and @PROBE_ZONE@ are the consumer's, because the probe directive
    # is module-specific: shield's is `shield_probe probezone;` and it needs a
    # `shield_ban_zone probezone:1m;` at http level to name that zone. A generic
    # scenario tree cannot hardcode either, so the consumer supplies them and
    # the scenarios only say WHERE they go. Empty is legitimate -- a module
    # whose probe needs no zone leaves PROBER_PROBE_ZONE unset.
    #
    # @BACKEND_PORT@ is the port a fake upstream bound, published by
    # prober_backend_start. It renders EMPTY when PROBER_BACKEND_PORT is unset,
    # and that is deliberate: a scenario with no backend is the normal case --
    # every scenario checked in today has none. Do NOT give this placeholder
    # @PROBE@'s bail-if-unset rule. @PROBE@ bails because an empty probe
    # location falls through to `location /` and the prober misreads that
    # handler's body as the probe document; an empty upstream port has no
    # equivalent silent-misdirection path, it simply fails nginx's config test
    # where the operator can read it.
    #
    # A conf that asks for @PROBE@ while the consumer supplied nothing must
    # bail, not render empty: an empty probe location falls through to
    # `location /`, the prober parses that handler's body as the probe document
    # and reports "malformed number". That misdirection is exactly the bug this
    # placeholder pair exists to end, so it fails loudly at render instead.
    if grep -q '@PROBE@' "$template" && [ -z "${PROBER_PROBE:-}" ]; then
        echo "Bail out! $template uses @PROBE@ but PROBER_PROBE is unset --" \
             "the consumer must supply its probe directive (e.g." \
             "PROBER_PROBE='shield_probe probezone;')"
        exit 1
    fi

    # Every value is escaped before it reaches sed's replacement side, where
    # `&` means "the whole matched text", `\` starts an escape and `#` closes
    # the s### expression. Unescaped, a probe directive containing `&` renders
    # the placeholder back into the output -- @PROBE@ would reach nginx as a
    # literal, which is the silent-failure mode this placeholder pair exists to
    # end. `#` is worse only in being loud. These are consumer-supplied values,
    # so the harness cannot assume they are tame.
    sed_repl() { printf '%s' "$1" | sed -e 's#[\\&/]#\\&#g' -e 's#\##\\\##g'; }

    sed -e "s#@LOAD@#$(sed_repl "$PROBER_LOAD")#" \
        -e "s#@PORT@#$(sed_repl "$PROBER_RESOLVED_PORT")#" \
        -e "s#@PREFIX@#$(sed_repl "$PROBER_PREFIX")#" \
        -e "s#@PROBE@#$(sed_repl "${PROBER_PROBE:-}")#" \
        -e "s#@PROBE_ZONE@#$(sed_repl "${PROBER_PROBE_ZONE:-}")#" \
        -e "s#@BACKEND_PORT@#$(sed_repl "${PROBER_BACKEND_PORT:-}")#" \
        "$template" > "$PROBER_PREFIX/conf/nginx.conf"
}

# prober_check_conf
#
# Two rendered-conf gates, each guarding an inference the engine relies on.
#
# The pid oracle compares the worker pid across each case and calls a change a
# crash. That inference only holds with ONE worker: with several, consecutive
# probe requests are answered by different live workers and every case fails on
# a server that is perfectly healthy. The conf comes from the consumer, so this
# cannot be enforced by shipping a conf -- check the rendered file instead, and
# bail rather than emit a wall of false failures. Trailing space is stripped
# separately: "worker_processes 1 ;" is valid nginx, and an untrimmed "1 "
# would not equal "1" and would bail a healthy conf.
#
# `daemon off;` is required because the engine backgrounds the binary itself
# and keeps $! as the master pid for teardown and for scenario drivers that
# send it signals. With daemon mode on, $! is a launcher that exits
# immediately: teardown kills nothing, the orphaned server keeps the port, and
# every later scenario fails on bind -- a confusing distance from the cause.
#
# PROBER_DAEMON_MODE=on inverts that one gate for the single scenario that
# CANNOT run under daemon off: a USR2 binary upgrade. nginx drops the
# NGX_CHANGEBIN signal when getppid()==ngx_parent (ngx_process.c), which always
# holds for a foreground master whose parent is prober_boot's `&` launcher, so
# the upgrade is silently ignored under daemon off. Opting in requires the
# conf to say `daemon on;` AND to write its pidfile to $PROBER_PREFIX/nginx.pid,
# because prober_boot then reads the master pid from that file instead of $!
# (the launcher exits and the master reparents away). Set it in the scenario's
# `env`, never globally: a daemonized server tracked by a stale $! is the
# orphaned-port failure this gate otherwise stops, and the scenario carries the
# pidfile-teardown contract in exchange.
prober_check_conf() {
    local workers

    workers="$(sed -n 's/^[[:space:]]*worker_processes[[:space:]]\+\([^;]*\);.*/\1/p' \
        "$PROBER_PREFIX/conf/nginx.conf" | tail -n 1 | tr -d '[:space:]')"

    # PROBER_ALLOW_MULTIWORKER lets a scenario opt into worker_processes > 1.
    # It exists for exactly one shape: a scenario whose POINT is behaviour across
    # the worker set (multi-worker), where every case carries `pid_may_change` so
    # the oracle asserts "same master" (ppid) instead of "same worker" (pid) --
    # see eval_pid_stable / assert.h. Set it in the scenario's `env` file, never
    # globally: a scenario that leaves the default strict pid oracle on ITS cases
    # and also has several workers is the wall-of-false-failures this gate exists
    # to stop, and the opt-in must be a deliberate per-scenario act, not a run
    # default. The gate cannot itself verify every case uses pid_may_change (it
    # runs before any rule is parsed), so this is a contract the scenario keeps,
    # documented at its `env`; the burst of pid-mismatch failures is the loud
    # symptom if it is broken.
    if [ -n "$workers" ] && [ "$workers" != "1" ] \
       && [ "${PROBER_ALLOW_MULTIWORKER:-0}" != "1" ]; then
        echo "Bail out! worker_processes is \"$workers\", but the pid oracle" \
             "requires exactly 1 -- with several workers a healthy server reports" \
             "a different pid per request and every case fails (set" \
             "PROBER_ALLOW_MULTIWORKER=1 in the scenario env if every case uses" \
             "pid_may_change)"
        exit 1
    fi

    if [ "${PROBER_DAEMON_MODE:-off}" = "on" ]; then
        # The USR2 opt-in: require daemon ON, and require the pidfile at the
        # path prober_boot reads. A conf that opts in but stays daemon-off would
        # still ignore the binary upgrade; one with no pidfile leaves teardown
        # with no master to kill (the launcher's $! is gone). Both are bailed
        # rather than left to surface as a hung upgrade or a leaked process.
        if ! grep -qE '^[[:space:]]*daemon[[:space:]]+on[[:space:]]*;' \
            "$PROBER_PREFIX/conf/nginx.conf"; then
            echo "Bail out! PROBER_DAEMON_MODE=on but the conf lacks" \
                 "\"daemon on;\" -- USR2 binary upgrade is ignored under daemon" \
                 "off (getppid()==ngx_parent for a foregrounded master)"
            exit 1
        fi
        if ! grep -qE "^[[:space:]]*pid[[:space:]]+$PROBER_PREFIX/nginx\.pid[[:space:]]*;" \
            "$PROBER_PREFIX/conf/nginx.conf"; then
            echo "Bail out! PROBER_DAEMON_MODE=on but the conf does not set" \
                 "\"pid $PROBER_PREFIX/nginx.pid;\" -- a daemonized master is not" \
                 "\$! and teardown reads the master pid from that file"
            exit 1
        fi
        return 0
    fi

    if ! grep -qE '^[[:space:]]*daemon[[:space:]]+off[[:space:]]*;' \
        "$PROBER_PREFIX/conf/nginx.conf"; then
        echo "Bail out! conf lacks \"daemon off;\" -- the engine tracks the" \
             "master by \$! and a daemonized server orphans itself past teardown"
        exit 1
    fi
}

# prober_wait_listen HOST PORT TIMEOUT_MS
#
# Returns 0 as soon as a TCP connect to HOST:PORT succeeds, 1 if TIMEOUT_MS
# elapses first. Prints nothing: callers are inside a TAP stream.
#
# The client is bash's /dev/tcp rather than nc, for the reason recorded in
# fakesrv_test.sh's header -- nc is not installed everywhere and the
# openbsd/traditional/ncat variants differ in ways that would make a readiness
# check succeed or fail for reasons unrelated to the listener.
#
# The wait is counted in ITERATIONS of a fixed small sleep, never as a
# difference of two wall-clock readings. A clock-budget loop runs a different
# program on a loaded runner than on an idle one: the same code performs fewer
# probes when each one is slower, so a timeout becomes a property of the host
# rather than of the listener, and the resulting flake reproduces nowhere. A
# fixed step means every host performs the same number of attempts.
prober_wait_listen() {
    local host="$1" port="$2" timeout_ms="$3"
    local step_ms=50 attempts i

    # Round up, and always attempt at least once: a timeout shorter than one
    # step would otherwise report failure without ever having tried to connect,
    # which reads as "not listening" for a port that is.
    attempts=$(( (timeout_ms + step_ms - 1) / step_ms ))
    [ "$attempts" -lt 1 ] && attempts=1

    for ((i = 0; i < attempts; i++)); do
        if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
            return 0
        fi
        sleep 0.05
    done

    return 1
}

# prober_probe_pid HOST PORT
#
# Echo the worker pid that answered a request to /__probe, or return 1.
#
# The probe endpoint reports the pid of the worker that served THAT request,
# which is the same field eval_pid_stable (assert.c:543) compares across a
# case. Reading it here rather than parsing `ps` or the pidfile means the
# driver's notion of "which worker is serving" is the assertion engine's
# notion: a drain oracle built on a different source could call a reload
# complete while the rule engine still disagrees about who answered.
#
# Deliberately greps the pid out rather than linking a JSON parser into shell:
# the probe body is emitted by ngx_test_probe.c as flat one-level JSON, and a
# driver that needed structure would be asking for the prober binary instead.
prober_probe_pid() {
    local host="$1" port="$2" body pid read_rc attempt
    local attempts="${PROBER_PROBE_ATTEMPTS:-3}"

    # A single probe can lose a race the endpoint is not responsible for: the
    # connect succeeds but the peer RSTs before the GET is written (the write
    # takes SIGPIPE -> exit 141, empty body) or before the reply is read (empty
    # body, non-124). Against a real nginx under a reload this is a transient --
    # the worker IS answering, this one connection just lost the race -- and a
    # single empty read here would falsely certify "no new worker". Retry a
    # bounded number of times; each attempt is independently `timeout`-bounded,
    # so the AUD-09 finiteness property holds (worst case attempts * bound, and
    # the outer prober_signal_wait budget is still consulted between calls). A
    # 124 timeout is NOT retried within a call: it already consumed the full
    # per-attempt budget and retrying would multiply the wait; it returns to the
    # caller, whose counted budget advances and re-probes. Observed on the
    # qemu-s390x self-test leg, where the python3 stub's ghost/real accept
    # ordering makes the RST race fire deterministically.
    for (( attempt = 0; attempt < attempts; attempt++ )); do

    # The read's EXIT STATUS is deliberately ignored; only the bytes matter.
    # A server closing a `Connection: close` response commonly RSTs once it has
    # sent everything, and `cat` then exits non-zero having already delivered a
    # complete body. Gating on that status throws away good reads: it fails
    # here about half the time against a real nginx, and the symptom -- a wait
    # that never sees the new worker -- looks exactly like a reload that did
    # not happen.
    # AUD-09: the read is BOUNDED. A bare `cat <&3` blocks until the peer
    # closes, so a probe endpoint that trickles a byte at a time or holds the
    # connection open would hang this single call forever -- and because
    # prober_signal_wait's counted budget only advances between calls, the outer
    # timeout would never be consulted. A single failed reload would then eat the
    # whole CI job. `timeout` caps one probe; the 2 s bound is generous for a
    # healthy in-worker probe yet finite. The bound is `PROBER_PROBE_TIMEOUT`
    # (default 2), tunable ONLY to accommodate a slow host -- e.g. the
    # qemu-user s390x self-test leg, where an emulated python3 stub's
    # accept+reply cycle can exceed 2 s and starve the read into a false 124.
    # It stays finite on every path, so the AUD-09 property (bounded, the outer
    # budget is always eventually consulted) holds for any value.
    #
    # The read's EXIT STATUS is captured and a TIMED-OUT read is treated as a
    # failure even if a partial body arrived. A stalling endpoint can emit
    # `"pid":1234` and then hold the connection open; without this check the pid
    # would be extracted from that partial body and the probe would falsely
    # certify a reload landed. `timeout` exits 124 on expiry, so any non-zero
    # status here means the peer did not deliver a complete response in the
    # budget, which is "no answer" -- not a pid to trust.
        # `trap '' PIPE` is load-bearing: a probe endpoint that answers WITHOUT
        # reading the request (writes its reply and closes -- as the self-test
        # stub does, and as a real server legitimately may on a `Connection:
        # close` response) can close the socket before this `printf` finishes
        # writing the GET. The write then takes SIGPIPE and, unhandled, kills
        # this command-substitution subshell -- discarding the reply that had
        # already arrived in the socket buffer (observed as a deterministic
        # rc=141 empty body on the qemu-s390x leg). Ignoring SIGPIPE lets the
        # write fail quietly and the `cat` still drain the buffered body.
        body="$(trap '' PIPE; exec 3<>"/dev/tcp/$host/$port" 2>/dev/null && {
            printf 'GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3 2>/dev/null
            timeout "${PROBER_PROBE_TIMEOUT:-2}" cat <&3
        } 2>/dev/null)"
        read_rc=$?

        # A non-zero status is only a "no answer" verdict when it is the TIMEOUT
        # (124). A clean `Connection: close` commonly RSTs after the full body
        # and cat exits non-zero HAVING delivered everything -- the case the
        # original code documents -- so that status must NOT reject a complete
        # body. On the timeout code, fail outright (see the no-retry-on-124 note
        # above); on any other non-zero, fall through and let the pid-extraction
        # be the verdict (a complete body still has its pid; a partial one does
        # not).
        if [ "$read_rc" -eq 124 ]; then
            return 1
        fi

        # `"pid": 1234` -- tolerate any spacing the emitter might use, though
        # ngx_test_probe.c:203 emits `"pid":%P` with none.
        pid="$(printf '%s' "$body" | grep -o '"pid"[[:space:]]*:[[:space:]]*[0-9]\+' \
               | grep -o '[0-9]\+$' | head -1)"

        # A pid was extracted -- that IS the success verdict.
        if [ -n "$pid" ]; then
            printf '%s\n' "$pid"
            return 0
        fi
        # No pid this attempt: an unreachable port, a lost RST race (empty
        # body), or a complete body genuinely lacking the field. The first two
        # are transient and worth a retry; the last will fail every attempt and
        # correctly returns 1 once the retries are exhausted.
    done

    # Every attempt failed to yield a pid: no worker pid could be established.
    return 1
}

# prober_signal_wait SIG PID HOST PORT TIMEOUT_MS
#
# Send SIG to the master, then wait until the reload has actually been ABSORBED
# -- a new worker is answering -- and return 0. Return 1 on timeout.
#
# Why this is not `kill -HUP $pid; sleep 1`:
#
# A signal is asynchronous. kill(1) returns as soon as the signal is queued,
# long before the master has forked a new worker, and well before the OLD
# worker has finished the requests it already had in flight. A scenario that
# asserts anything after a bare `kill` is asserting against whichever of the
# two workers happened to win a race, and it will pass on an idle box and fail
# on a loaded one -- the failure nobody can reproduce.
#
# The oracle is the probe endpoint's own pid field: before the signal we record
# which worker is serving, then poll until a DIFFERENT pid answers. That is the
# definition of "the reload landed" that agrees with the assertion engine, and
# it needs no new C and no pidfile parsing.
#
# Fixed 50 ms steps with a counted iteration budget, never a wall-clock diff.
# A clock-budget loop runs a different program on a loaded runner than on an
# idle one, so a timeout flake reproduces nowhere; prober_wait_listen above
# takes the same shape for the same reason.
#
# NOTE for scenario authors: after this returns, the worker pid HAS changed on
# purpose. The worker-survival oracle runs on every prober case and its strict
# form calls that a crash, so any case spanning this call must carry
# `pid_may_change`, which relaxes it to "still a child of the same master".
# Cases before and after the reload should NOT carry it -- the strict form is
# still the stronger assertion, and the directive is per-case so that the
# relaxation is scoped to the boundary itself.
#
# It does NOT catch a crash: a SIGKILLed worker's replacement has the same
# master as a reloaded one, so a segfault inside the spanning case reads as ok.
# If the scenario has to catch that too, assert it separately.
prober_signal_wait() {
    local sig="$1" pid="$2" host="$3" port="$4" timeout_ms="$5"
    local step_ms=50 attempts i before after

    # Record the serving worker BEFORE signalling. Failing here is fatal to the
    # wait rather than silently degrading to a sleep: without a `before` value
    # there is nothing for "a different pid answered" to be different from, and
    # returning 0 anyway would hand the caller a reload that may not have
    # happened -- the vacuous-gate shape this repo keeps re-learning.
    before="$(prober_probe_pid "$host" "$port")" || return 1

    kill -"$sig" "$pid" 2>/dev/null || return 1

    attempts=$(( (timeout_ms + step_ms - 1) / step_ms ))
    [ "$attempts" -lt 1 ] && attempts=1

    for ((i = 0; i < attempts; i++)); do
        sleep 0.05

        # A reloading master briefly has no worker able to answer; a failed
        # probe is "not yet", not a verdict. Only a SUCCESSFUL read of a
        # different pid ends the wait.
        after="$(prober_probe_pid "$host" "$port")" || continue

        if [ "$after" != "$before" ]; then
            return 0
        fi
    done

    return 1
}

# prober_boot
#
# Sets: PROBER_SERVER_PID. Config-tests first so a broken conf is a bail-out
# with the actual error, not a connect timeout.
prober_boot() {
    if ! "$PROBER_SERVER_BIN" -t -p "$PROBER_PREFIX" -c conf/nginx.conf \
        >"$PROBER_PREFIX/logs/conftest" 2>&1; then
        echo "Bail out! config test failed:"
        sed 's/^/# /' "$PROBER_PREFIX/logs/conftest"
        exit 1
    fi

    "$PROBER_SERVER_BIN" -p "$PROBER_PREFIX" -c conf/nginx.conf &
    PROBER_SERVER_PID=$!

    # Under the daemon-on opt-in the process just backgrounded is the LAUNCHER,
    # not the master: it double-forks the real master and exits, so $! reaps in
    # a moment and the master reparents to init. Wait the launcher out (its exit
    # is normal, status ignored), then adopt the master pid from the pidfile the
    # conf was gated to write. Everything downstream -- the readiness loop, the
    # driver's signal target, teardown -- then tracks the master by that pid.
    if [ "${PROBER_DAEMON_MODE:-off}" = "on" ]; then
        wait "$PROBER_SERVER_PID" 2>/dev/null || true
        PROBER_SERVER_PID=""

        local _p _pid
        for _p in $(seq 1 50); do
            if [ -s "$PROBER_PREFIX/nginx.pid" ]; then
                _pid="$(tr -d '[:space:]' < "$PROBER_PREFIX/nginx.pid")"
                if [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null; then
                    PROBER_SERVER_PID="$_pid"
                    break
                fi
            fi
            sleep 0.1
        done

        if [ -z "$PROBER_SERVER_PID" ]; then
            echo "Bail out! daemon-on master never wrote a live pid to" \
                 "$PROBER_PREFIX/nginx.pid"
            if [ -f "$PROBER_PREFIX/logs/error.log" ]; then
                sed 's/^/# /' "$PROBER_PREFIX/logs/error.log"
            fi
            exit 1
        fi
    fi

    # Wait for the listener rather than sleeping a fixed interval: a fixed
    # sleep is either slow or flaky, and on a loaded CI box it is both. Verify
    # after each connect that the server is still alive: a stale listener on the
    # port can answer TCP connects while our server exited on bind() failure.
    local _i
    for _i in $(seq 1 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$PROBER_RESOLVED_PORT") 2>/dev/null; then
            if kill -0 "$PROBER_SERVER_PID" 2>/dev/null; then
                break
            fi
            # Server is dead but listener answered. Stale listener; retry.
        fi
        sleep 0.1
    done

    # Final check: server must still be alive.
    if ! kill -0 "$PROBER_SERVER_PID" 2>/dev/null; then
        echo "Bail out! server failed to start (pid $PROBER_SERVER_PID exited):"
        if [ -f "$PROBER_PREFIX/logs/error.log" ]; then
            sed 's/^/# /' "$PROBER_PREFIX/logs/error.log"
        fi
        exit 1
    fi
}

# prober_stop
#
# Stop the server synchronously rather than leaving it to an EXIT trap. kill(1)
# only delivers TERM; without waiting for the process to actually go, the
# script can return while workers are still writing out their .gcda files, and
# the coverage job downstream then reads a partial profile. Waiting also means
# the error-log scrape reads a file nobody is still appending to.
prober_stop() {
    # A daemon-off master is our child: kill $! and `wait` reaps it.
    if [ "${PROBER_DAEMON_MODE:-off}" != "on" ]; then
        kill "$PROBER_SERVER_PID" 2>/dev/null || true
        wait "$PROBER_SERVER_PID" 2>/dev/null || true
        return 0
    fi

    # A daemon-on master reparented to init after the launcher exited, so `wait`
    # cannot reap it -- poll until it is actually gone (prober_backend_stop's
    # shape), so the log/journal scrape that follows reads a settled process.
    #
    # Crucially, the master to kill is read from the pidfile HERE, not taken
    # from PROBER_SERVER_PID. A USR2 scenario replaces the master mid-run: the
    # new generation writes a fresh nginx.pid and the old one moves to
    # nginx.pid.oldbin. A driver runs in a subprocess, so any PROBER_SERVER_PID
    # it re-adopted does not reach this teardown in the parent -- trusting the
    # variable would kill the retired master and LEAK the live one, holding the
    # port past the run. Killing every pid named by both files, plus the
    # variable, covers all three: the current master, a not-yet-retired oldbin,
    # and the daemon-off fallback value.
    local _p _pid _targets=""
    for _p in "$PROBER_PREFIX/nginx.pid" "$PROBER_PREFIX/nginx.pid.oldbin"; do
        [ -s "$_p" ] || continue
        _pid="$(tr -d '[:space:]' < "$_p" 2>/dev/null)"
        [ -n "$_pid" ] && _targets="$_targets $_pid"
    done
    [ -n "${PROBER_SERVER_PID:-}" ] && _targets="$_targets $PROBER_SERVER_PID"

    for _pid in $_targets; do
        kill "$_pid" 2>/dev/null || true
    done
    for _p in $(seq 1 50); do
        _pid=""
        for _pid in $_targets; do
            kill -0 "$_pid" 2>/dev/null && break
            _pid=""
        done
        [ -z "$_pid" ] && break
        sleep 0.1
    done
    for _pid in $_targets; do
        kill -9 "$_pid" 2>/dev/null || true
    done
}

# prober_scrape_log
#
# Returns 1 if the error log holds an unexempted alert/crit/emerg line.
#
# Surfaces what the HTTP responses cannot show. A worker that exits on a
# signal, finalizes a request twice or reuses a busy buffer logs at [alert] or
# [crit] and then carries on serving; the next request is answered by a
# respawned worker and every assertion in the run still passes. Without this
# the suite is green and the bug ships. It is a default, not an opt-in, because
# the failure mode it catches is precisely the one nobody thinks to enable a
# check for.
#
# [crit] is in the set deliberately: nginx logs slab exhaustion at [crit],
# which is the single most common real symptom of an unchecked shm allocation.
# Rules that provoke that ON PURPOSE -- a fault injector arming an allocation
# failure -- must therefore be able to exempt the line they expect, or the gate
# would fail every suite that tests its module's out-of-memory path.
# PROBER_ALLOW_LOG is that opt-out: an extended regex, matched per line, whose
# hits are reported but not fatal. Scoped to the pattern rather than a blanket
# off switch, so exempting "no memory" still leaves a segfault in the same run
# fatal.
prober_scrape_log() {
    local log="$PROBER_PREFIX/logs/error.log" scrape allowed

    [ -f "$log" ] || return 0

    scrape="$(grep -E '\[(alert|crit|emerg)\]' "$log" || true)"

    if [ -n "${PROBER_ALLOW_LOG:-}" ] && [ -n "$scrape" ]; then
        allowed="$(printf '%s\n' "$scrape" | grep -E "$PROBER_ALLOW_LOG" || true)"
        scrape="$(printf '%s\n' "$scrape" | grep -vE "$PROBER_ALLOW_LOG" || true)"

        if [ -n "$allowed" ]; then
            echo "# error-log lines exempted by PROBER_ALLOW_LOG:"
            printf '%s\n' "$allowed" | sed 's/^/# /'
        fi
    fi

    if [ -n "$scrape" ]; then
        echo "# server logged alert/crit/emerg:"
        printf '%s\n' "$scrape" | sed 's/^/# /'
        return 1
    fi

    return 0
}

# prober_backend_start SCRIPT
#
# Sets: PROBER_BACKEND_PID PROBER_BACKEND_PORT PROBER_BACKEND_JOURNAL
#
# Boots fakesrv on an ephemeral port against SCRIPT and waits for it to accept.
# The caller owns teardown via prober_backend_stop.
#
# A missing SCRIPT is fatal. This is the load-bearing line in the function: the
# alternative -- carrying on with no backend -- produces a scenario that boots,
# serves, and passes every assertion that does not happen to need the upstream,
# under a name claiming the upstream was exercised. That is the vacuous-gate
# failure mode this repo keeps re-learning, and here it would be permanent,
# because nothing downstream can distinguish "the backend said nothing" from
# "there was no backend".
prober_backend_start() {
    local script="$1" portfile port

    if [ ! -f "$script" ]; then
        echo "Bail out! no backend script at $script -- a scenario that asks" \
             "for a backend must ship one; running on without it would pass" \
             "by testing the no-upstream path under the wrong name"
        exit 1
    fi

    if [ ! -x ./fakesrv ]; then
        echo "Bail out! no fakesrv binary -- run prober/build.sh first"
        exit 1
    fi

    portfile="$PROBER_PREFIX/backend.port"
    PROBER_BACKEND_JOURNAL="$PROBER_PREFIX/backend.jsonl"

    # Port 0: the kernel picks a free one and fakesrv publishes it. Hardcoding
    # a port makes two scenarios running at once fail on bind, and the failure
    # surfaces as a connect error in whichever one lost.
    ./fakesrv -script "$script" -listen 127.0.0.1:0 \
              -portfile "$portfile" \
              -journal "$PROBER_BACKEND_JOURNAL" \
              -errfile "$PROBER_PREFIX/backend.err" &
    PROBER_BACKEND_PID=$!

    # Wait for the portfile to become NON-EMPTY, not merely to exist. fakesrv
    # writes it tmp+fsync+rename precisely so a reader never sees a partial
    # file, but a reader that accepts a zero-length one parses "" as a port and
    # then connects to port 0 -- the 1-in-20 flake fakesrv.c:37 documents.
    local _i
    for ((_i = 0; _i < 100; _i++)); do
        if [ -s "$portfile" ]; then
            break
        fi
        if ! kill -0 "$PROBER_BACKEND_PID" 2>/dev/null; then
            echo "Bail out! fakesrv exited before publishing a port:"
            [ -f "$PROBER_PREFIX/backend.err" ] &&
                sed 's/^/# /' "$PROBER_PREFIX/backend.err"
            exit 1
        fi
        sleep 0.05
    done

    port="$(cat "$portfile" 2>/dev/null || true)"

    case "$port" in
        ''|*[!0-9]*)
            echo "Bail out! fakesrv published no usable port (read \"$port\")"
            exit 1 ;;
    esac

    PROBER_BACKEND_PORT="$port"

    if ! prober_wait_listen 127.0.0.1 "$PROBER_BACKEND_PORT" 5000; then
        echo "Bail out! fakesrv published port $PROBER_BACKEND_PORT but is not" \
             "accepting connections"
        exit 1
    fi
}

# prober_backend_stop
#
# Mirrors prober_stop: TERM, then wait for the process to actually go, so the
# journal and errfile are complete before anything reads them. Tolerates an
# already-dead pid -- a scenario that kills the backend on purpose must not
# then fail in teardown.
prober_backend_stop() {
    [ -n "${PROBER_BACKEND_PID:-}" ] || return 0

    kill "$PROBER_BACKEND_PID" 2>/dev/null || true
    wait "$PROBER_BACKEND_PID" 2>/dev/null || true
}

# prober_backend_scrape
#
# Returns 1 if the backend reported an error or died during the scenario.
#
# Shaped like prober_scrape_log: `# `-prefixed TAP diagnostics, non-zero on a
# finding. It reads -errfile, which is where fakesrv's die() lands -- a script
# it could not parse, a fault action it did not recognise, a socket call that
# failed. Those are silent otherwise: the daemon is backgrounded, its stdout is
# barred by rule 1, and a scenario whose upstream died mid-run sees only
# connection errors from the module under test, which reads as a module bug.
#
# A backend that is no longer alive at scrape time is itself a finding, for the
# same reason. PROBER_BACKEND_ALLOW_EXIT is the opt-out for scenarios that
# terminate it deliberately; scoped to that one claim like PROBER_ALLOW_LOG,
# never a blanket off switch -- an exempted exit still leaves a parse error in
# the same run fatal.
prober_backend_scrape() {
    local errfile="$PROBER_PREFIX/backend.err" scrape rc=0

    if [ -n "${PROBER_BACKEND_PID:-}" ] &&
       ! kill -0 "$PROBER_BACKEND_PID" 2>/dev/null &&
       [ -z "${PROBER_BACKEND_ALLOW_EXIT:-}" ]; then
        echo "# fake upstream exited before teardown (pid $PROBER_BACKEND_PID)"
        rc=1
    fi

    if [ -f "$errfile" ]; then
        scrape="$(grep -v '^[[:space:]]*$' "$errfile" || true)"

        if [ -n "$scrape" ]; then
            echo "# fake upstream reported errors:"
            printf '%s\n' "$scrape" | sed 's/^/# /'
            rc=1
        fi
    fi

    return "$rc"
}

# prober_cleanup
#
# Idempotent teardown of everything a scenario allocated: fake upstream,
# server, prefix. Installed as ONE trap by the caller, before the first
# resource exists -- which is what closes the window a trap-per-resource
# ladder leaves open, where a failure between two installs leaks whatever the
# earlier one owned.
#
# Saves and restores $? as its very first and very last act. An EXIT trap's
# own exit status becomes the script's, so a single unguarded command in here
# -- a kill on an already-reaped pid is enough -- turns a failing scenario
# green, or a passing one red, with every assertion in the TAP stream still
# reading ok. That is not hypothetical: it is exactly what P1-B3's own gate
# hit. Hence every command below is guarded and the function ends with an
# explicit `return`, never with the status of whatever ran last.
#
# Trap install stays in the CALLER. A library that installs its own trap
# silently overwrites the caller's -- see prober_render_conf's note.
prober_cleanup() {
    local rc=$?

    prober_backend_stop || true

    if [ -n "${PROBER_SERVER_PID:-}" ]; then
        prober_stop || true
    fi

    # Only a prefix this harness created is removed. An inherited one is left
    # alone -- see prober_make_prefix for how a foreign value gets in.
    if [ -n "${PROBER_PREFIX:-}" ] && [ -n "${PROBER_PREFIX_OWNED:-}" ]; then
        rm -rf "$PROBER_PREFIX" || true
    fi

    # A second call must be a no-op rather than a second teardown: the caller
    # may run this inline at the end of a happy path AND have it fire again on
    # EXIT. Clearing the handles is what makes the guards above hold.
    PROBER_BACKEND_PID=""
    PROBER_SERVER_PID=""
    PROBER_PREFIX=""
    PROBER_PREFIX_OWNED=""

    return "$rc"
}
