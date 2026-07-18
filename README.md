# nginx-test-harness

Functional + leak testing for nginx and Angie modules, in C, with no Perl and
no version banner sniffing.

You compile a small **probe** into your module's test build. It answers one
special HTTP request with a JSON snapshot of the worker's internals: pid, open
file descriptors, memory-pool usage, shared-memory slab accounting. A
standalone **prober** binary sends your test requests, takes a snapshot before
and after each one, and asserts that the difference is exactly zero. If your
module leaks an fd or a byte of long-lived memory per request, the delta is
nonzero and the test goes red — in CI, not in production three weeks later.

## The problem, in plain terms

Three gaps this closes, in the order they hurt:

**Leaks that sanitizers cannot see.** ASan and valgrind watch *memory*. A
leaked file descriptor is not a memory error, so they say nothing while your
worker crawls toward `worker_rlimit_nofile`. Same for a slab page lost in a
shared-memory zone. And nginx's own pool design hides a third kind: every
request gets its own memory pool that is freed wholesale when the request
ends, so a per-request leak inside it looks like a flat line from outside.
That is why the probe measures the **cycle pool** — the one that lives as
long as the worker and where normal request handling should never allocate.
Any nonzero cycle-pool delta across a request is unbounded growth, full stop.

**Angie has no functional coverage.** Stock `Test::Nginx::Socket` probes `-V`
and requires `nginx version: ...`; Angie answers `Angie version: Angie/1.12.0`
and the suite bails before the first test. The prober reads no banner, so the
same rule files run against both servers unchanged.

**Allocation-failure paths are untested.** `malloc` does not fail in CI, so
the branches that handle a full slab or a failed `ngx_palloc` only ever
execute on a box under real pressure. The probe can arm a fault injector at
those sites and make "out of memory" just another test case.

## How it fits together

```
prober (standalone binary)          nginx/Angie worker (test build only)
┌──────────────────────┐            ┌────────────────────────────────┐
│ rule files           │  HTTP/1.1  │ your module (.so)              │
│ raw sockets          │ ─────────► │  + ngx_test_probe.c            │
│ strict JSON reader   │ ◄───────── │    renders pid/fds/pools/slab  │
│ delta oracle · TAP   │   JSON     │    as JSON on a test directive │
└──────────────────────┘            └────────────────────────────────┘
```

- **`src/ngx_test_probe.{c,h}`** — the in-worker probe, compiled into the
  module under test. Renders worker and shm-zone state as JSON so a test can
  assert on things the HTTP response never reveals.
- **`prober/`** — the standalone C prober. Rule files, raw sockets, an
  RFC 8259-strict JSON reader (24 self-tests), TAP output. Knows nothing
  about any particular module.

## Mini howto: from zero to a passing leak test

Five steps. Step 2 is the only C you write, and most of it is copy-paste.

**1. Add the harness to your module repo as a submodule:**

```sh
git submodule add https://github.com/myguard-labs/nginx-test-harness t/harness
```

**2. Give the probe an HTTP surface.** An nginx module cannot inherit another
module's command table, so you add one directive and a tiny content handler
that calls `ngx_test_probe_json()`. Roughly 60 lines, all behind
`#ifdef NGX_TEST_HARNESS`, in one file (say `src/ngx_mymod_probe_hooks.c`).
Copy the worked example:
[`src/ngx_shield_probe_hooks.c`](https://github.com/myguard-labs/nginx-http-shield-module/blob/main/src/ngx_shield_probe_hooks.c)
in the shield module — swap the names, delete the hooks you don't need.

Optionally register hooks for what the probe cannot know generically:

```c
static u_char *
my_zone_render(u_char *buf, u_char *last, ngx_shm_zone_t *zone)
{
    /* appends to the "zone" object -- leading comma, no closing brace */
    return ngx_slprintf(buf, last, ",\"nodes\":%ui", my_count(zone));
}

static const ngx_test_probe_hooks_t  my_hooks = {
    .zone_render = my_zone_render,   /* extra module fields in the JSON */
    .fault_set   = my_fault_set,     /* arm allocation faults on demand */
};

ngx_test_probe_register(&my_hooks);
```

Both hooks are **optional**. Registering nothing still gets you the whole
generic document — flavor, pid, connections, `fds`, cycle-pool stats, and the
zone's name, size and slab page accounting. That is already enough for fd and
memory leak assertions without a line of module-specific C. Slab occupancy
works for any zone because every nginx shm zone begins with an
`ngx_slab_pool_t`.

**3. Build the test flavor of your module.** Compile
`t/harness/src/ngx_test_probe.c` and `t/harness/src/ngx_test_probe_arm.c`
alongside your sources with `-DNGX_TEST_HARNESS`. Without the define,
everything — probe, hooks, directive — compiles out to nothing (see
[Never ship it](#never-ship-it)).

**4. Write a rule file**, e.g. `t/prober/rules/00-smoke.rule`:

```
name    a plain request leaks no fd and no cycle-pool memory
from    127.0.0.20
send    GET / HTTP/1.1\r\n
send    Host: prober\r\nConnection: close\r\n\r\n
expect  status=200
delta   fds == 0
delta   pool.cycle_used == 0
```

`probe` lines assert on a single snapshot, `delta` lines on the change across
the case. `from` binds the source address — load-bearing for anything keyed
on the peer: without varying it, a per-IP fault never fires and the case
passes for the wrong reason. Your test nginx.conf **must** set
`worker_processes 1;` and `daemon off;` (the runner checks and bails
otherwise — see [Consumer contract](#consumer-contract)).

**5. Build the prober and run:**

```sh
( cd t/harness/prober && ./build.sh )     # builds prober + json_test
PROBER_MODULE=ngx_http_mymod_module.so \
PROBER_DIRECTIVE=mymod_probe \
t/harness/prober/run.sh nginx 1.31.3
```

Output is TAP: one `ok`/`not ok` per rule, `prove`-consumable. Most consumers
wrap this in a ~15-line `t/prober/run.sh` that exports the `PROBER_*`
variables and execs the harness runner.

`run.sh` refuses to start when any of three preflight gates fail, because
each failure mode once produced a green run that proved nothing:

1. the prober binary is not older than its sources (it does not build them);
2. the JSON reader passes its own self-tests — it is the **oracle** every
   assertion runs through, so a lax reader makes the whole suite unable to fail;
3. the module binary actually carries the probe directive, decided by
   inspecting the binary rather than by whether a `.so` happens to exist.

## Scenarios

`run.sh` is the single-scenario form: one conf, one rule glob, one boot. When
what varies is the *environment* — a tiny shm zone, an `LD_PRELOAD`, an
rlimit, a signal choreography — a flat rule list cannot express it, and
Perl-style one-boot-per-test-file wastes a server boot on every case that
didn't need one. Scenarios split the difference: one boot per **environment**,
many cases inside it.

A scenario is a directory; every file is optional except that a scenario must
end up with something to assert (rules or a driver):

```
scenarios/zone-exhaustion/
    nginx.conf    conf template with @LOAD@/@PORT@   (default: $PROBER_CONF)
    *.rule        cases run by the prober            (default: $PROBER_RULES)
    env           sourced before boot: LD_PRELOAD, ulimit, PROBER_ALLOW_LOG
    driver.sh     replaces the prober call: signal choreography (see below)
    requires      gate; nonzero exit = scenario SKIPPED, not failed
```

- `prober/run-scenario.sh <dir> [flavor] [version]` runs one scenario.
- `prober/test-scenarios.sh [flavor] [version]` runs every directory matching
  `PROBER_SCENARIOS` (default `scenarios/*/`) and aggregates to a single TAP
  stream, each scenario an indented subtest block — `prove`-consumable. Zero
  matching scenarios is a bail-out, not a green: a typo'd glob must not turn
  the stage into a silent no-op.

`driver.sh` is the orchestration layer. It runs with the server already booted
and gets the master pid, so it can interleave prober runs with signals —
reload under traffic, binary upgrade, worker kill — and assert what happens.
Its stdout is the scenario's TAP; its exit status is the verdict. Exported
contract: `PROBER_CLIENT` (the prober binary), `PROBER_LIB` (lib.sh, for
`prober_stop` and friends), `PROBER_SCENARIO`, `PROBER_PREFIX` (logs +
pidfile live under it), `PROBER_SERVER_BIN`, `PROBER_SERVER_PID`,
`PROBER_RESOLVED_PORT`.

Two engine-level gates apply to every scenario, because each guards an
inference the harness depends on: `worker_processes 1` (the pid oracle) and
`daemon off;` (the engine tracks the master by `$!`; a daemonized server
orphans itself past teardown and holds the port into the next scenario). The
error-log scrape runs per scenario, `PROBER_ALLOW_LOG` and all.

All three entry points share the same engine (`prober/lib.sh`), so boot,
teardown and the log scrape cannot drift apart between them.

## Consumer contract

One nginx.conf requirement and one environment variable must be honored for
the harness to run correctly:

**`worker_processes 1` (required in consumer conf)**

The pid oracle — which asserts that the worker pid does not change across
consecutive probe requests — only holds with a single worker process. With
multiple workers, the same healthy server answers each request with a
different worker, changing the reported pid on every case and causing
universal test failure. Because the consumer supplies the nginx.conf, this
cannot be enforced by shipping a default configuration. `run.sh` parses the
rendered config file and exits with a bail-out before the first case if
`worker_processes` is not exactly `1`.

**`PROBER_ALLOW_LOG` (environment variable, optional)**

By default, `run.sh` treats any `[alert]`, `[crit]`, or `[emerg]` line in the
error log as a test failure — because a worker that crashes, finalizes a
request twice, or reuses a busy buffer logs at one of these levels, then
carries on serving. Without this gate, the suite passes while the bug ships.

However, fault-injection tests intentionally provoke failures to exercise
out-of-memory and allocation-failure paths. These tests arm the fault
injector to exhaustion, which nginx logs at `[crit]`, and the test must pass
despite the error. Set `PROBER_ALLOW_LOG` to an extended regex matching the
expected error line(s). Each matching line is reported in the test output but
not counted as a failure. The regex is matched per line against the full
error log scrape, so a pattern like `"no memory for"` exempts that specific
condition while leaving segfaults and other unexpected errors fatal.

```sh
PROBER_ALLOW_LOG='no memory for|slab' prober/run.sh nginx 1.31.3
```

## Gotchas worth knowing before you hit them

- **An "unavailable" sentinel cancels under a delta.** `fds` is `-1` when
  `/proc` is unreadable. Direct assertions on it fail loudly; `delta fds == 0`
  would subtract `-1` from `-1` and pass. The prober rejects it explicitly.
- **A delta rule fails loudly when the probe lacks the field** — running new
  rules against an older server gives "delta path not present", not a silent
  pass.
- **Measure the cycle pool, not the request pool.** See above.
- **ASan needs `detect_leaks=0`.** nginx never frees its configuration pool, so
  LeakSanitizer reports the whole config parse as leaked and turns `nginx -t`
  into a bail-out. Everything else ASan catches stays on.

## Never ship it

The whole feature compiles out unless `NGX_TEST_HARNESS` is defined, and it
must stay that way in packaged builds: the probe walks queues under the slab
mutex, scans `/proc`, and exposes internal state unauthenticated. Before a
release, `strings` your production `.so` for `ngx_test_probe` — it must not
be there.

## See also

- [nginx-http-shield-module](https://github.com/myguard-labs/nginx-http-shield-module)
  — first consumer; its `t/prober/` rules and probe-hooks file are a worked
  example.
- [Introduction article on deb.myguard.nl](https://deb.myguard.nl/articles/nginx-test-harness/)
  — the tour: what it catches, why sanitizers miss it, and the traps.
- [Where to find us](https://deb.myguard.nl/where-to-find-us/) — all our repos,
  packages and Docker images in one place.
