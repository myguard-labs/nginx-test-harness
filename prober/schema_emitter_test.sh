#!/usr/bin/env bash
#
# TAP self-test: the schema describes the EMITTER, not just the fixtures.
#
# schema_test.c checks two fixtures against ../probe-schema.json. Both live in
# this repo and are edited by the same hand, so they can agree with each other
# while having drifted away from the code that actually renders the document:
# rename a member in ngx_test_probe_json() and neither notices. This closes
# that loop by reading the format strings in ../src/ngx_test_probe.c.
#
# Grep rather than a compile-and-run: the emitter needs real nginx headers and
# a configured build to execute, which is the runtime leg's job. The member
# NAMES, though, are literal text in the format strings, and a rename is
# exactly the drift being guarded against -- so matching them as text catches
# the failure this suite exists for without needing a server.
set -euo pipefail

cd "$(dirname "$0")"

EMITTER=../src/ngx_test_probe.c
SCHEMA=../probe-schema.json

PLANNED=18
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

# Leaf members, as they appear inside the emitter's format strings. Nested
# paths are checked by their leaf name: the emitter renders `"total":%ui`
# inside the connections object, so the text to look for is `"total"`, while
# the schema spells the same field `connections.total`.
#
#   <schema path>:<leaf name as the emitter writes it>
FIELDS="
flavor:flavor
flavor_version:flavor_version
pid:pid
page_size:page_size
connections:connections
connections.total:total
connections.free:free
fds:fds
pool:pool
pool.cycle_used:cycle_used
pool.cycle_blocks:cycle_blocks
pool.cycle_large:cycle_large
zone:zone
zone.present:present
zone.name:name
zone.size:size
zone.slab_pages_free:slab_pages_free
"

for entry in $FIELDS; do
    path=${entry%%:*}
    leaf=${entry##*:}

    # The emitter writes members as \"leaf\": inside a C string literal.
    if grep -q "\\\\\"$leaf\\\\\":" "$EMITTER" \
        && grep -q "\"$path\"" "$SCHEMA"; then
        ok 0 "\"$path\" is emitted and named by the schema"
    else
        if ! grep -q "\\\\\"$leaf\\\\\":" "$EMITTER"; then
            ok 1 "\"$path\": schema names it but $EMITTER does not emit \"$leaf\""
        else
            ok 1 "\"$path\": emitted but the schema does not name it"
        fi
    fi
done

# The reverse sweep: any member the emitter renders that the schema never
# mentions. Without this the schema decays into a passing subset -- every
# check above stays green while the document grows fields nobody wrote down.
#
# Module-hook members are rendered by the consuming module via zone_render, not
# by this file, so everything found here is legitimately ours to declare.
unknown=""
for leaf in $(grep -oE '\\"[a-z_]+\\":' "$EMITTER" | sed 's/\\"//g; s/://' | sort -u); do
    if ! grep -q "\"[a-z_.]*$leaf\"" "$SCHEMA"; then
        unknown="$unknown $leaf"
    fi
done

if [ -z "$unknown" ]; then
    ok 0 "the emitter renders no member the schema fails to name"
else
    ok 1 "the emitter renders members the schema does not name:$unknown"
fi

if [ "$tests_run" -ne "$PLANNED" ]; then
    echo "# ran $tests_run tests but the plan says $PLANNED"
    exit 1
fi

[ "$failures" -eq 0 ] || exit 1
