#!/usr/bin/env bash
#
# TAP self-test for the fakesrv daemon.
#
# backend_test.c proves the codecs and the script parser as pure functions.
# What it structurally cannot reach is everything this file exists for: that
# the daemon binds a port and writes it where a scenario can find it, that a
# real client on a real socket gets the reply the codec built, that the faults
# actually fire on the wire, and that the journal records what happened. A fake
# upstream whose codecs are perfect and whose socket handling is broken passes
# backend_test completely.
#
# Clients here are bash's /dev/tcp rather than nc, which is not installed
# everywhere and differs across the openbsd/traditional/ncat variants in ways
# that would make this suite pass or fail for reasons unrelated to the daemon.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=19
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
SRV_PID=""

cleanup() {
    if [ -n "$SRV_PID" ] && kill -0 "$SRV_PID" 2>/dev/null; then
        kill "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

./build.sh >/dev/null

#
# Start fakesrv on port 0 and wait for the portfile.
#
# Polling for the file is the whole reason the daemon writes it atomically:
# a non-atomic write is visible as a zero-length file, and this loop would then
# read an empty port about one run in twenty.
#
start_srv() {
    local script="$1"
    shift

    rm -f "$WORK/port" "$WORK/journal" "$WORK/err"

    ./fakesrv -script "$script" \
              -listen 127.0.0.1:0 \
              -portfile "$WORK/port" \
              -journal "$WORK/journal" \
              -errfile "$WORK/err" \
              "$@" >/dev/null 2>&1 &

    SRV_PID=$!

    for _ in $(seq 1 100); do
        if [ -s "$WORK/port" ]; then
            PORT="$(cat "$WORK/port")"
            return 0
        fi
        sleep 0.05
    done

    return 1
}

stop_srv() {
    if [ -n "$SRV_PID" ]; then
        kill "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
        SRV_PID=""
    fi
}

# Send $2 to the daemon and print whatever comes back, giving up after $3
# seconds so a hung daemon fails this suite rather than the whole CI job.
talk() {
    local port="$1" payload="$2" timeout="${3:-2}"

    exec 3<>"/dev/tcp/127.0.0.1/$port" || return 1

    printf '%b' "$payload" >&3

    timeout "$timeout" cat <&3 || true

    exec 3<&- 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
}

# ---- memcached, no faults ---------------------------------------------------

cat >"$WORK/mc.backend" <<'EOF'
proto   memcached
seed    hello  world
EOF

if start_srv "$WORK/mc.backend"; then st=0; else st=1; fi
ok "$st" "the daemon starts and writes its port"

case "$PORT" in
    ''|*[!0-9]*) ok 1 "the portfile holds a numeric port" ;;
    *)           ok 0 "the portfile holds a numeric port" ;;
esac

out="$(talk "$PORT" 'get hello\r\n')"
if [ "$out" = "$(printf 'VALUE hello 0 5\r\nworld\r\nEND\r')" ]; then st=0; else st=1; fi
ok "$st" "a get hit is served over a real socket"

out="$(talk "$PORT" 'get absent\r\n')"
if [ "$out" = "$(printf 'END\r')" ]; then st=0; else st=1; fi
ok "$st" "a get miss is served over a real socket"

# A set followed by a get on the SAME connection: proves the store is real and
# that the daemon keeps reading after answering, which a one-shot reply loop
# would fail.
out="$(talk "$PORT" 'set k 0 0 3\r\nabc\r\nget k\r\n')"
if printf '%s' "$out" | grep -q 'STORED'; then st=0; else st=1; fi
ok "$st" "a set is acknowledged"
if printf '%s' "$out" | grep -q 'VALUE k 0 3'; then st=0; else st=1; fi
ok "$st" "a value set on one connection is readable on the same connection"

# Pipelining: two commands in one write must draw two replies.
out="$(talk "$PORT" 'get hello\r\nversion\r\n')"
if printf '%s' "$out" | grep -q 'VALUE hello'; then st=0; else st=1; fi
ok "$st" "the first of two pipelined commands is answered"
if printf '%s' "$out" | grep -q 'VERSION'; then st=0; else st=1; fi
ok "$st" "the second of two pipelined commands is answered"

stop_srv

if grep -q '"ev":"listen"' "$WORK/journal"; then st=0; else st=1; fi
ok "$st" "the journal records the listen event"

if grep -q '"ev":"cmd".*"cmd":"get"' "$WORK/journal"; then st=0; else st=1; fi
ok "$st" "the journal records commands"

if grep -q '"ev":"summary"' "$WORK/journal"; then st=0; else st=1; fi
ok "$st" "the journal ends with a summary record"

# The load-bearing claim: the summary's accept count is what makes a keepalive
# assertion falsifiable. Four connections were opened above.
accepts="$(sed -n 's/.*"accepts":\([0-9]*\).*/\1/p' "$WORK/journal" | tail -1)"
if [ "$accepts" = "4" ]; then st=0; else st=1; fi
ok "$st" "the summary counts one accept per connection (got ${accepts:-none})"

if [ ! -s "$WORK/err" ]; then st=0; else st=1; fi
ok "$st" "a clean run writes nothing to the errfile"

# ---- the portfile is never observable as zero-length ------------------------
#
# The atomicity property, tested directly rather than through its symptom.
#
# The daemon writes PATH.tmp, fsyncs and renames. Written in place instead, the
# file is briefly visible with no contents, and the polling loop in start_srv --
# and in every scenario that will use this daemon -- reads an empty port. It
# reproduces roughly one run in twenty, which is exactly the frequency at which
# a CI leg gets disabled rather than fixed.
#
# A start/stop loop cannot see that window reliably, so this watches the file
# from the moment the daemon is launched and fails on ANY sighting of an
# existing-but-empty portfile. `-s` is the whole assertion: `-e` would pass on
# precisely the broken state.
portfile_race_seen=0

for _attempt in 1 2 3 4 5; do
    rm -f "$WORK/racecheck"

    ./fakesrv -script "$WORK/mc.backend" -listen 127.0.0.1:0 \
              -portfile "$WORK/racecheck" >/dev/null 2>&1 &
    race_pid=$!

    for _ in $(seq 1 400); do
        if [ -e "$WORK/racecheck" ] && [ ! -s "$WORK/racecheck" ]; then
            portfile_race_seen=1
            break
        fi
        if [ -s "$WORK/racecheck" ]; then
            break
        fi
    done

    kill "$race_pid" 2>/dev/null || true
    wait "$race_pid" 2>/dev/null || true

    [ "$portfile_race_seen" -eq 1 ] && break
done

if [ "$portfile_race_seen" -eq 0 ]; then st=0; else st=1; fi
ok "$st" "the portfile is never visible as an existing empty file"

# ---- faults actually fire on the wire ---------------------------------------

cat >"$WORK/rst.backend" <<'EOF'
proto   memcached
seed    hello  world
fault   on=get:1  action=rst
EOF

start_srv "$WORK/rst.backend"

# The reset arrives as a failed read rather than as data. What must NOT happen
# is a well-formed reply: that would mean the fault was parsed and dropped.
#
# Written as an if rather than `grep -q ...; [ $? -ne 0 ]` -- that idiom reads
# the exit status of the TEST, not of the grep, so it is always true and the
# assertion passes no matter what the daemon sent.
out="$(talk "$PORT" 'get hello\r\n' 2>/dev/null || true)"
if printf '%s' "$out" | grep -q 'VALUE'; then
    ok 1 "an rst fault suppresses the reply"
else
    ok 0 "an rst fault suppresses the reply"
fi

stop_srv

# ---- truncate ---------------------------------------------------------------

cat >"$WORK/trunc.backend" <<'EOF'
proto   memcached
seed    hello  world
fault   on=get:1  action=truncate  after=8
EOF

start_srv "$WORK/trunc.backend"

out="$(talk "$PORT" 'get hello\r\n' 2>/dev/null || true)"
if [ "${#out}" -le 8 ]; then st=0; else st=1; fi
ok "$st" "a truncate fault cuts the reply short (got ${#out} bytes)"

stop_srv

# ---- redis ------------------------------------------------------------------
#
# SC2016 is disabled per-line below: the single quotes around the RESP frames
# are load-bearing. `$3` and `$5` are bulk-string length markers in the
# protocol, not shell variables -- expanding them is what must not happen.

cat >"$WORK/redis.backend" <<'EOF'
proto   redis
seed    hello  world
EOF

start_srv "$WORK/redis.backend"

# shellcheck disable=SC2016
out="$(talk "$PORT" '*2\r\n$3\r\nGET\r\n$5\r\nhello\r\n')"
# shellcheck disable=SC2016
if [ "$out" = "$(printf '$5\r\nworld\r')" ]; then st=0; else st=1; fi
ok "$st" "a RESP get hit is served over a real socket"

# shellcheck disable=SC2016
out="$(talk "$PORT" '*2\r\n$3\r\nGET\r\n$6\r\nabsent\r\n')"
# shellcheck disable=SC2016
if [ "$out" = "$(printf '$-1\r')" ]; then st=0; else st=1; fi
ok "$st" "a RESP get miss serves the nil bulk string"

stop_srv

# ---- a bad script must not boot ---------------------------------------------

cat >"$WORK/bad.backend" <<'EOF'
proto   memcached
fault   on=get:1  action=nonesuch
EOF

if ./fakesrv -script "$WORK/bad.backend" -listen 127.0.0.1:0 \
             -portfile "$WORK/badport" >/dev/null 2>&1; then
    ok 1 "a script with an unknown action refuses to boot"
else
    ok 0 "a script with an unknown action refuses to boot"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    exit 1
fi

[ "$failures" -eq 0 ]
