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
that calls `ngx_test_probe_json()`. Roughly 120 lines of boilerplate, all behind
`#ifdef NGX_TEST_HARNESS`. Copy from:

- **Template (recommended):** Start with [`PROBE_HTTP_TEMPLATE.c`](PROBE_HTTP_TEMPLATE.c)
  in this repo. It is fully documented and ready to fill in — just rename it,
  swap module names, and update three struct pointers.
- **Worked example (if you need asymmetric hooks):** See
  [`src/ngx_shield_probe_hooks.c`](https://github.com/myguard-labs/nginx-http-shield-module/blob/main/src/ngx_shield_probe_hooks.c)
  in the shield module for a production consumer. Use the template first; copy
  from shield only if your module needs custom zone introspection or
  fault injection that differs from the generic model.

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

**Buffer sizing in the HTTP handler.** When you allocate a buffer for the
response, size it as:

```c
size_t size = NGX_TEST_PROBE_JSON_MAX + zone->shm.name.len + N;
```

where `N` accounts for your `zone_render` hook's output (if any). The generic
document is bounded by `NGX_TEST_PROBE_JSON_MAX`; a zero-hook consumer adds only
the zone name length. If your hook appends fixed-width data (e.g.,
"`,"nodes":123456789`"), add ~128 bytes for safety. Undersizing truncates the
JSON in the harness (ngx_slprintf stops at `last`), which surfaces as a parse
error on every case — not wrong assertions on one. The template provides this
formula with detailed comments.

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

`send` lines concatenate into one buffer and reach the socket in a single
write, so splitting a request across several `send` lines does **not** split it
on the wire. To actually stall mid-request, use `pause <ms>`:

```
name    headers arriving late do not leak a connection
send    GET / HTTP/1.1\r\n
pause   200
send    Host: prober\r\nConnection: close\r\n\r\n
expect  status=200
delta   fds == 0
```

`pause` stalls at the byte offset where it appears: the request line goes out,
the connection sits idle for 200 ms, then the headers follow. That split is
what makes request-header timeouts, partial-header handling and smuggling
windows reachable at all. A `pause` before the first `send` stalls before any
byte is written (the server's pre-request idle timeout); one after the last
holds the connection open with a complete request already sent. Each pause is
1–10000 ms and a case's pauses may not sum past 10000 ms — a stall longer than
the prober's own read timeout would report a harness timeout rather than
whatever the server did, so the rule file is rejected at load time instead.

Where `pause` puts one gap on the wire, `send_slow <chunk> <ms>` dribbles a span
of the request in fixed-size pieces — the slowloris shape, where the server's
read path is entered once per chunk instead of a handful of times:

```text
name       a dribbled header block still completes
send       GET / HTTP/1.1\r\n
send_slow  4 20
send       Host: prober\r\nConnection: close\r\n\r\n
expect     status=200
delta      fds == 0
```

`send_slow` paces from where it appears up to the next `pause`/`send_slow` (or
the end of the request), writing `chunk` bytes at a time with `ms` between —
plus one leading stall, so it reads like `pause` at the point it appears. A
chunk at or above the remaining length degrades to a single write after that
stall. Chunks are 1–4096 bytes.

The pacing is costed **per chunk** against the same 10000 ms ceiling, so a
dribble long enough to outlast the read timeout is rejected at load time. That
cost depends on bytes added *after* the directive, so the check runs once more
when the stanza closes — a case that looked cheap on its `send_slow` line can
still be rejected after a later `send` makes it expensive.

This asserts that a slow request is served *correctly*; it does not assert that
one is eventually cut off. Timeout policy is the consumer's, not the harness's.
See `rules/stock/slowloris.rule`.

`shutdown 0|1|2` calls `shutdown(2)` once the request is on the wire — `0` =
SHUT_RD, `1` = SHUT_WR, `2` = SHUT_RDWR. One per case:

```text
name      a half-closed request is still answered
send      POST /upload HTTP/1.1\r\nHost: prober\r\n\r\nbody
shutdown  1
expect    status=200
delta     fds == 0
```

`shutdown 1` is the useful one: it half-closes the sending side, which is what
tells a server reading to EOF that the body is complete *without* tearing the
connection down — the response still arrives. `0` and `2` are accepted for
completeness, but a case using them is asserting on what the server logged and
on `delta` counters, not on a response it will not see.

`abort <offset>` writes the first `<offset>` request bytes and then destroys the
connection with a TCP reset (`SO_LINGER{1,0}`), so the server sees `ECONNRESET`
rather than a clean close:

```text
name          a reset mid-header-block is cleaned up
send          GET /__probe HTTP/1.1\r\nHost: prober\r\n
abort         24
delta         fds == 0
no_error_log  (assertion|panic|segfault)
```

This is the client-vanishes primitive: it tests that a server releases a
request's resources when the peer disappears, instead of holding them until a
timeout expires. A graceful EOF arrives where the event loop expects one; a
reset can land anywhere, including mid-parse. Offset `0` resets before the first
byte, an offset past the request end sends all of it and then resets, and pauses
inside the written prefix still apply — so `send_slow` followed by `abort` is a
slowloris that gives up.

An aborted case has **no response**, so it may not carry `expect`, `expect_not`
or `error_code_like`; the parser rejects that at load time. An `expect_not` in
particular would otherwise pass unconditionally against an empty buffer,
reporting green for an assertion that tested nothing. Judge an aborted case with
`delta` / `probe` / `no_error_log` / `grep_error_log` — evidence the server
itself produced. For the same reason `abort` and `shutdown` are mutually
exclusive: a half-close asks to be answered, a reset says the client is gone.
See `rules/stock/abort.rule`.

`recv_slow <chunk> <ms>` paces the READ side — take `chunk` bytes, hold off
`ms`, repeat — and `so_rcvbuf <bytes>` shrinks the client's receive window:

```text
name       a slow reader still gets its whole response
send       GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
so_rcvbuf  512
recv_slow  256 40
expect     status=200
delta      fds == 0
```

This is the mirror of `send_slow`, and it tests the other half of the server. A
client that stops draining its socket applies **backpressure**: the server's send
buffer fills, its write blocks or returns `EAGAIN`, and the response sits
half-delivered while the event loop must keep the connection alive without
spinning on it. A module can handle every malformed request correctly and still
burn a worker on a slow reader.

The two directives only work as a pair. With the default receive buffer the
kernel absorbs a modest response whole, so `recv_slow` alone delays when the
*prober* sees the bytes while the server never blocks — nothing is under test.
`so_rcvbuf` is what makes the stall reach the far end. Note the kernel doubles
the requested size and enforces its own floor, so the effective window is not the
number given; assert on behaviour, never on the size. See
`rules/stock/slow-reader.rule`.

`recv_slow` is mutually exclusive with `abort` — a reset connection is never read
from, so pacing its reads would pace nothing.

Beyond `expect status=` / `body~` / `header~`, a case can also carry:

```
expect          raw_response_headers_like~^Content-Type:.*text
expect_not      body~stack smashing
expect_not      header~X-Debug
error_code_like ^(403|429)$
no_error_log    \[emerg\]
grep_error_log  banned by rule
xfail           issue #12: trailer parsing not implemented yet
```

- **`expect raw_response_headers_like~`** — POSIX extended regex against the
  raw HTTP header block (CRLF-delimited lines, no status line, no body). Useful
  for asserting header order, duplicates, or byte-level framing that a substring
  match cannot express. The header block is NUL-terminated but may contain
  embedded NULs in header values; the regex matches the full block as-is.
- **`expect_not`** — the negative form of `expect` (`body~`, `header~` only):
  the case fails if the pattern IS found. Status has no negative form here on
  purpose; a negated status is a set, and sets are spelled with
  `error_code_like`.
- **`error_code_like`** — POSIX extended regex against the status code as
  decimal text, for rules that accept a class (`^2[0-9]{2}$`) rather than one
  value. An unparseable status line is matchable as the literal `-1`. Invalid
  regexes are rejected at load time, before the first request goes out.
- **`no_error_log` / `grep_error_log`** — per-case error-log assertions: no
  line / at least one line written **during this case** may/must match the
  regex. The prober records the log file offset before the case's request and
  greps only that slice, so an earlier case's lines can neither satisfy nor
  trip these. Needs the log path (`prober -e`, or `PROBER_ERROR_LOG`, which
  `run.sh` exports automatically); a case carrying either directive fails
  loudly when the path is missing. They complement — not replace — the
  whole-run alert/crit/emerg gate below.
- **`xfail [reason]`** — known-broken case: it still runs, but a failure is
  reported as `not ok N # TODO reason` and does not fail the suite. If it
  unexpectedly passes, the line reads `ok N # TODO reason`, which TAP
  consumers surface as "unexpectedly succeeded" — the signal to remove the
  annotation.

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

## Stock rules

`rules/stock/` holds rule families that hold for **any** module, so a
consumer gets them without writing them. `PROBER_RULES` is word-split by
`run.sh`, so several space-separated globs compose:

```sh
PROBER_RULES="t/harness/rules/stock/*.rule t/prober/rules/*.rule" \
PROBER_MODULE=ngx_http_mymod_module.so \
PROBER_DIRECTIVE=mymod_probe \
t/harness/prober/run.sh nginx 1.31.3
```

They target `/__probe` — the one location every consumer already has — so
they need no extra `location` block, no upstream, and no per-consumer status
knob.

| File | Family |
|---|---|
| `malformed-http.rule` | Hostile request-line and header framing: NUL bytes, bare LF, oversized headers, smuggling header pairs |
| `malformed-body.rule` | Malformed chunked framing: non-hex, negative and oversized chunk sizes |
| `head-no-body.rule` | HEAD reports a GET's headers and emits no body |
| `huge-content-length.rule` | `Content-Length` of 2^31−1, 2^32+1, 2^63−1, past 2^64 and negative, with no body sent |

### What may live there

Only assertions that are module-independent, which in practice means
**nginx's own parser rejected the request before any module ran**. A 400
from a NUL byte in the URI is core behaviour and is identical for every
consumer.

What may not live there is any **handler-level verdict** — the status a
module chooses for a request nginx accepted. Shield answers 403 to an
absolute-form request target; another module answers 200, 404 or 502 to the
same bytes. Two of shield's ten malformed cases were dropped on exactly that
ground rather than hoisted.

That line is not where intuition puts it, and it was drawn by measurement.
Three results are worth knowing before writing a stock case, because each
one would have produced a rule that passes for the wrong reason:

- **Bare LF line endings are accepted**, not rejected — nginx takes a bare
  LF as a line terminator, so the request reaches the handler.
- **`%00` is rejected in the URI path but accepted in the query string**,
  since only the path is percent-decoded during normalization.
- **A bad chunk size is only rejected if a handler actually reads the
  body.** The same request answers 400 at a `proxy_pass` location, 405 at a
  GET-only one and 404 where nothing matches. That is why the chunked cases
  assert survival and deltas rather than a status, and why they are a
  separate file.

Cases that cannot assert a status assert worker survival and clean deltas
instead, which holds whether the consumer's location proxies, returns or
serves a file.

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

**`ngx_test_probe_arm()` in zero-hook mode (optional)**

If your module registers no `fault_set` hook (zero-hook mode — the generic
probe alone suffices), you **should still call `ngx_test_probe_arm()`** from
your HTTP handler before rendering the snapshot. The harness allows a later
hook registration to arm or disarm faults, so a test that calls `arm()` now
can always be extended with a custom hook later without changing the test
code. If no hook is registered, the call is a no-op and returns `NGX_DECLINED`;
if a hook is later added, it takes effect immediately.

Call it in your HTTP handler as:

```c
(void) ngx_test_probe_arm(mlcf->probe_zone, &r->args);
```

The `&r->args` parse the HTTP query string for fault directives (e.g.,
`?fault_slab=5`). The return value is ignorable — both `NGX_OK` and
`NGX_DECLINED` are success. The timing matters: call `arm()` *before*
rendering the snapshot, so the response reflects the armed state.

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
