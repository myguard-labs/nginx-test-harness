#!/usr/bin/env bash
#
# TAP self-test: prober_render_conf() substitutes every placeholder a scenario
# conf is allowed to use.
#
# This exists because @PREFIX@ was NOT substituted for the entire life of the
# scenario tree. Every scenario conf sets `pid`/`error_log` under @PREFIX@, so
# the literal string reached nginx, open() failed, and the config test bailed
# before a single request ran. Nothing in this repo executes the scenario tree
# -- it runs in consuming module repos -- so the breakage was invisible here.
#
# The guard is therefore two-sided: the placeholders the renderer claims to
# handle must actually be replaced (a rendered conf carrying a literal @NAME@
# is the bug), and every @NAME@ appearing in any checked-in scenario conf must
# be one the renderer knows. The second half is what turns a future scenario
# using @UPSTREAM@ into a red test instead of another silent bail.
set -euo pipefail

cd "$(dirname "$0")"

PLANNED=8
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

diag() { printf '# %s\n' "$1"; }

# The placeholders prober_render_conf() is contracted to substitute. Keep in
# sync with the sed in lib.sh; the last test asserts the scenario tree uses
# nothing outside this set.
KNOWN="LOAD PORT PREFIX"

# shellcheck source=lib.sh
. ./lib.sh

# Minimal stand-ins: the renderer only cares that the variables are set.
PROBER_LOAD="load_module /nowhere/mod.so;"
PROBER_RESOLVED_PORT=18099

TMPL="$(mktemp "${TMPDIR:-/tmp}/render_tmpl.XXXXXX")"
cat > "$TMPL" <<'EOF'
@LOAD@
pid @PREFIX@/nginx.pid;
error_log @PREFIX@/logs/error.log info;
http { server { listen 127.0.0.1:@PORT@; } }
EOF

prober_render_conf "$TMPL"
RENDERED="$PROBER_PREFIX/conf/nginx.conf"

if [ -f "$RENDERED" ]; then ok 0 "the renderer writes a conf"
else ok 1 "the renderer writes a conf"; fi

# No placeholder survives rendering. This is the assertion that was missing.
if grep -q '@[A-Z_]\+@' "$RENDERED"; then
    diag "unsubstituted: $(grep -o '@[A-Z_]\+@' "$RENDERED" | sort -u | tr '\n' ' ')"
    ok 1 "no placeholder survives rendering"
else
    ok 0 "no placeholder survives rendering"
fi

grep -q "^load_module /nowhere/mod.so;" "$RENDERED"
ok $? "@LOAD@ is substituted"

grep -q "listen 127.0.0.1:18099;" "$RENDERED"
ok $? "@PORT@ is substituted"

grep -q "^pid $PROBER_PREFIX/nginx.pid;" "$RENDERED"
ok $? "@PREFIX@ is substituted in pid"

grep -q "^error_log $PROBER_PREFIX/logs/error.log info;" "$RENDERED"
ok $? "@PREFIX@ is substituted on every line it appears"

# The prefix must be the real per-run directory, not a literal or a relative
# path: nginx resolves a relative path against its compiled-in prefix, which
# would put the pidfile outside the sandbox.
case "$PROBER_PREFIX" in
    /*) ok 0 "the substituted prefix is absolute" ;;
    *)  diag "prefix is not absolute: $PROBER_PREFIX"
        ok 1 "the substituted prefix is absolute" ;;
esac

# Every placeholder used by a checked-in scenario conf must be known to the
# renderer. A new scenario reaching for @UPSTREAM@ fails here rather than
# bailing at nginx's config test with an open() error.
unknown=""
for used in $(grep -ho '@[A-Z_]\+@' scenarios/*/nginx.conf 2>/dev/null \
              | tr -d '@' | sort -u); do
    case " $KNOWN " in
        *" $used "*) ;;
        *) unknown="$unknown $used" ;;
    esac
done

if [ -n "$unknown" ]; then
    diag "scenario confs use placeholders the renderer does not substitute:$unknown"
    ok 1 "every scenario placeholder is known to the renderer"
else
    ok 0 "every scenario placeholder is known to the renderer"
fi

rm -f "$TMPL"
rm -rf "$PROBER_PREFIX"

if [ "$tests_run" -ne "$PLANNED" ]; then
    diag "planned $PLANNED tests, ran $tests_run"
    exit 1
fi

[ "$failures" -eq 0 ]
