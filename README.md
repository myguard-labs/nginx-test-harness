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
- **`prober/fakesrv`** — a scriptable fake redis/memcached upstream, for
  modules that talk to a cache. Serves correct replies by default and takes
  adversarial fault overlays (truncation, lying lengths, resets, idle closes)
  that a real daemon cannot be made to produce, plus a JSONL journal that makes
  connection reuse falsifiable. See [Fake upstream](#fake-upstream-proberfakesrv).

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
the case. `probe_baseline` lines subtract like `delta`, but from a snapshot
taken once before the first case of the run — see
[Catching a slow leak](#catching-a-slow-leak). `from` binds the source
address — load-bearing for anything keyed on the peer: without varying it, a per-IP fault never fires and the case
passes for the wrong reason. Your test nginx.conf **must** set
`worker_processes 1;` and `daemon off;` (the runner checks and bails
otherwise — see [Consumer contract](#consumer-contract)).

### Catching a slow leak

`delta` has one blind spot, and it is the shape most real leaks take. It reads
its before-snapshot **per case**, so a resource that grows by one unit on every
case is already present in both of that case's reads. The subtraction cancels,
every `delta fds == 0` in the file passes, and the count climbs from 0 to 200
across a 200-case run without a single red line.

`probe_baseline <path> <op> <value>` subtracts from a fixed origin instead: one
snapshot taken before the first case runs, held for the whole run. The same leak
that is invisible per case fails on whichever case crosses the bound.

```text
name            a request leaks no descriptor of its own
send            GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
expect          status=200
delta           fds == 0

name            ... and neither did any request before it
send            GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
expect          status=200
delta           fds == 0
probe_baseline  fds <= 2
```

Every case carries the `delta`; only the last carries the `probe_baseline`.
With two cases the difference is small — the point is what happens when the
file has two hundred of them, where a one-descriptor-per-case drip leaves every
`delta` at zero and lands the baseline at 200.

The two are complements, not alternatives. `delta` localises a jump to the case
that caused it; `probe_baseline` bounds the total. Writing both, as above, tells
you *which* case leaked and *that* the run stayed inside its budget.

Two things to get right:

**Usually a bound, not `== 0`.** A scenario that legitimately warms a cache,
opens a keepalive connection or faults in a slab page has an honest non-zero
floor by the second case. `probe_baseline fds == 0` fails there against
perfectly correct behaviour. Measure what a healthy run actually reaches and
bound slightly above it — the same discipline the absolute floors in
`scenarios/conn-delta` needed.

**Usually on the last case.** The bound is only interesting once the run has had
enough cases to accumulate something. Putting it on every case is not wrong, but
it makes the earliest case the one that reports the failure, which is rarely the
one that caused it.

The origin is read before any case, so it precedes every `fault` the file arms —
unlike `delta`'s before-snapshot, which is deliberately taken *after* arming so a
counter reset does not read as a leak. A fault counter is therefore visible to a
`probe_baseline` and not to a `delta`. If the origin snapshot cannot be read the
run aborts rather than starting: a `probe_baseline` with nothing to subtract from
would silently assert nothing.

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
`delta` / `probe_baseline` / `probe` / `no_error_log` / `grep_error_log` —
evidence the server itself produced. For the same reason `abort` and `shutdown` are mutually
exclusive: a half-close asks to be answered, a reset says the client is gone.
See `rules/stock/abort.rule`.

`hold <ms>` writes the whole request, then waits that long without reading a
single byte before closing normally:

```text
name          a completed request whose client stops listening
send          GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
hold          200
delta         fds == 0
no_error_log  (assertion|panic|segfault)
```

This is the third way a client can walk away, and deliberately the polite one.
`abort` resets, so no response can be written at all. `shutdown` half-closes,
and the response still arrives. `hold` does neither: the connection stays fully
open and idle while the server writes a response nobody will ever read, and only
then ends with an ordinary FIN.

What that catches is a server holding a completed request's resources because it
keys cleanup off an error or an EOF — and here it sees neither, just a peer that
asked a question and left without waiting for the answer. Nothing is wrong at
the TCP level for the event loop to react to, which is exactly what makes it a
different path from the two directives above.

Like `abort`, a held case is **never read**, so it may not carry `expect`,
`expect_not` or `error_code_like` — same vacuous-assertion trap, reached a
different way, and rejected at load time for the same reason. The difference is
worth keeping straight: with `abort` the response does not exist, with `hold` it
exists and was simply never collected. Either way it is not there to assert on.

`hold` is mutually exclusive with `abort` (a reset destroys the connection
`hold` means to keep open) and with `recv_slow` (which paces a read loop `hold`
skips entirely). The wait counts against the same total-stall ceiling as
`send_slow`, so it cannot be spent on top of the budget. See
`rules/stock/abandoned-response.rule`.

A **send-then-drop client** — one that writes a complete request and closes
without reading a byte, distinct from `abort`'s reset — is `hold` with the
shortest wait the case needs, not a separate directive: the FIN is ordinary and
the response is left uncollected exactly as above. The wait is there only to give
the server time to finish writing before the close; a case that wants the drop as
immediate as the harness can make it uses `hold 1`.

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

`recv_slow` is mutually exclusive with `abort` and `hold` — neither reads the
connection at all, so pacing their reads would pace nothing.

`pid_may_change` relaxes the worker-survival oracle for one case, from "the same
worker answered both probe reads" to "the worker answering now is still a child
of the same master":

```text
name        the reload does not drop the connection
send        GET /slow HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
pid_may_change
expect      status=200
```

Every case is checked for worker survival, whether or not it asks: a worker that
segfaults mid-request is respawned by the master, and the retry the client never
sees can still produce the status and body the rule asked for, so the case would
report `ok` on a module that crashed. A changed pid is that crash.

A **reload changes the worker pid on purpose**, so a case spanning a `SIGHUP`, a
binary upgrade, or a conf with several workers fails the strict form while doing
exactly what the scenario asked. `pid_may_change` is for those cases and no
others. It takes no arguments, is off by default, and is **per case** — put it on
the stanza that crosses the signal, not on the ones before and after, which
should keep the stronger assertion.

It relaxes the oracle rather than removing it: the after-worker must still be a
child of the same master, so the probe port being answered by an unrelated
server is caught, and a probe document missing `ppid` fails the case instead of
passing quietly. What it **does not** catch is a crash — a worker killed and
respawned by the same master keeps that master's pid, so a segfault inside a
case carrying this directive reads as `ok`. A scenario that has to catch a crash
across the reload asserts it another way (a `no_error_log` on the worker-exit
message, or a delta a respawned worker could not satisfy). Note the directive
raises the floor on the probe contract — `ppid` is rendered by the generic half
of the probe, so a consumer gets it by rebuilding against the harness, with no
change to its own template.

`dechunk` decodes a `Transfer-Encoding: chunked` response body before the body
assertions run, so `body~`, `expect_not body~` and `body_sha256=` see the
payload rather than the chunk size lines:

```text
name        a chunked response decodes to the expected payload
send        GET /chunked HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
dechunk
expect      status=200
expect      body_sha256=2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

It takes no arguments and is off by default, so no rule written before it existed
changes meaning. The raw wire bytes stay reachable — decoding writes to a
separate buffer rather than over the response — because a harness built to
provoke invalid framing has to be able to assert on what actually arrived.

A framing error fails the case on its own, before the body assertions are
judged, and names which rule the server broke: a malformed or overflowing size
line, chunk data not followed by CRLF, a chunk shorter than its declared size,
or no terminating 0-chunk. That last one is the interesting failure — every
chunk parsed cleanly and only the terminator is missing, which is precisely how
a truncated response looks to anything that validates just the chunks it did
receive. A `dechunk` on a response that is *not* chunked also fails, rather than
passing quietly: a decode oracle that skips itself is not an oracle.

`gunzip` inflates a `Content-Encoding: gzip` or `Content-Encoding: deflate`
response body before the body assertions run, so `body~`, `expect_not body~` and
`body_sha256=` see the decompressed payload rather than the compressed stream:

```text
name        a gzip response inflates to the expected payload
send        GET /compressed HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
gunzip
expect      status=200
expect      body~hello
```

It takes no arguments and is off by default, so no rule written before it existed
changes meaning. It **chains after `dechunk`**: a `Transfer-Encoding: chunked`
response that is also `Content-Encoding: gzip` needs its framing removed before
the compressed stream is coherent, so write `dechunk` then `gunzip` and the body
oracles read the inflated bytes. Both `gzip` and `deflate` (zlib-wrapped and raw
headerless) are handled. The compressed wire bytes stay reachable, exactly as
with `dechunk` — inflation writes to a separate buffer.

A decode error fails the case on its own, before the body assertions are judged,
and names the failure: not a valid gzip/deflate stream, or a stream that ended
before its terminator. That truncated case is the sharp one — the stream inflates
cleanly up to where it was cut, which is exactly how a response dropped
mid-transfer looks to anything that trusts the bytes it did receive. A `gunzip`
on a response that carries no compression header fails rather than passing
quietly, for the same reason `dechunk` does.

`expect_close_within <ms>` asserts the **server** ended the connection within
that long of the request going on the wire:

```text
name                 a completed request has its connection closed promptly
send                 GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
expect               status=200
expect_close_within  2000
delta                fds == 0
```

Every rule here already asks for `Connection: close`; this is what checks the
server did it, and by when. The response bytes are identical whether the
connection was released promptly, released far too late, or is still held open —
so a module that keeps a reference after the response is written (an uncancelled
timer, a cleanup handler that never runs) passes every other assertion. Even the
fd delta can be back to baseline by the time the probe runs, having been leaked
for seconds.

It judges *how* the connection ended, not what came back, and reports the three
outcomes distinctly: a close inside the deadline passes; a close after it fails
**with the measured time**; and a connection still open at the deadline fails as
that. A reset counts as closed — the connection is gone — but a late one is
named as a reset, since a server that resets is not merely slow.

That last outcome is why the directive changes a read timeout from a transport
error into a result. Without it the read gives up, the case aborts with "request
failed", and the assertion that asked the question never runs — a real server
defect reported as a harness fault. The opt-in is per case: every rule without
the directive reads a non-closing server exactly as before.

The deadline is measured from the **last request byte**, so a case that
deliberately dribbles with `pause` or `send_slow` is not billed for its own
pacing. Bounded two ways, both because a deadline that cannot be missed is an
assertion that cannot go red: the directive caps at 10000 ms at parse time, and
the run **bails** if any case's deadline is at or past the read timeout (`-t`,
default 5000 ms) — the read would give up first and report a timeout whatever
the server did. That second check needs both numbers, so it happens after the
rule files load rather than in the parser; `prober --check -t <ms>` validates
the combination without booting a server.

Mutually exclusive with `abort` and `hold` — neither ever reads the socket, so
the server's close is unobservable and the deadline would judge nothing. `hold`
looks like the natural pairing and the *idea* is right, but observing an
idle-but-open connection needs a read-side wait rather than hold's blind sleep;
that is `expect_idle`, below. The pairing that works today is `shutdown 1` — half-close, keep reading, and assert the server closes its half on time. See
`rules/stock/close-deadline.rule`.

`expect_idle <ms>` is the opposite oracle on the same connection state: it
asserts the server left the connection **open and silent** for that long,
rather than acting on it.

```text
name             an unterminated request is neither answered nor hung up on
send             GET /__probe HTTP/1.1\r\nHost: prober\r\n
expect_idle      300
delta            fds == 0
```

A module that mis-drives the event loop fails in one of two directions, and
only one was testable before. An over-eager cleanup — a timer armed on the
wrong branch, a handler reading "no data yet" as "peer is gone" — closes a
connection that should have stayed open. An over-eager response path answers a
request whose headers were never terminated. Both look like a perfectly valid
exchange from the client's side; what marks a correct server here is that it
does *nothing*, which no other directive could observe.

The wait **polls without reading**. Draining would defeat it twice over: the
response bytes would be collected, so the case could no longer assert the
server stayed silent, and the read would consume the very readiness being
asserted about. The connection is left exactly as an idle client leaves it.

Three outcomes, again distinct because they are three different bugs: nothing
arrived and the connection stayed open passes; data arriving fails **naming
that the server answered**; a close arriving fails with the measured time and
the manner (FIN or reset). Data or a close ends the wait immediately rather
than at the deadline.

Like the close deadline it is measured from the last request byte and capped at
10000 ms, and the run bails if a case's wait is at or past `-t`. That bound is
weaker here and for a different reason: `poll()` answers to its own deadline, so
a long wait is *not* truncated and the assertion stays falsifiable — but a case
quietly parking longer than the per-request budget stalls the run somewhere
nobody thinks to look.

Mutually exclusive with `abort`, `hold`, `recv_slow`, `expect_close_within`, and
response expectations. The first three never observe the socket; the fourth
asserts the opposite outcome, so whichever assertion ran first would decide the
verdict; response expectations would assert against a buffer that is empty by
construction — and `expect_not` would report green having looked at nothing. It
*does* combine with `shutdown 1`, though note a half-close on an *incomplete*
request is a truncated request, which a healthy server answers with 400 rather
than ignoring. See `rules/stock/idle-connection.rule`.

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

Two more directives shape the request itself rather than the assertions on it:

- **`repeat <count> <text>`** — append `text` to the request `count` times,
  with the same `\r`/`\n`/`\t`/`\\`/`\"`/`\0`/`\xNN` escapes `send` accepts.
  This is how a case reaches a limit without a thousand-line rule file: a
  header block that overruns `large_client_header_buffers`, a body longer than
  `client_max_body_size`, a pathological repetition that makes a parser go
  quadratic. `count` is 1–100000, and the whole token must be the number —
  `10junk` is rejected at load time rather than quietly parsed as `10`, since
  a size-driven case that silently changes size is exactly how a limit test
  stops reaching its limit.

  ```text
  name    an over-long header block is rejected, not crashed
  send    GET / HTTP/1.1\r\nHost: prober\r\n
  repeat  2000 X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n
  send    \r\n
  expect  status=400
  delta   fds == 0
  ```

- **`fault <query>`** — arm the module's fault injector before the case runs.
  The prober issues its own `GET /__probe?<query>` first, requires a 200, and
  only then takes the before-snapshot and sends the case's request — so a
  counter the arming request itself moved is not billed to the case. The reply
  to the arming request is discarded: what it did is judged by the case's own
  `probe` and `delta` assertions.

  ```text
  name    a slab allocation failure is handled, not fatal
  fault   fault_slab=1
  send    GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n
  delta   fds == 0
  ```

  The query string is the module's own vocabulary, not the harness's — the
  harness only delivers it. Allocation-failure branches are the least-tested
  code in any module, and this is what makes them reachable without a
  debugger. The whole arming request must fit in 512 bytes; a longer query is
  a rule-file mistake and is reported as one.

**5. Check the rules parse, without a server:**

```sh
prober/prober --check rules/*.rule
# 12 cases parsed from 3 rule files
```

`--check` runs the rule files through the same loader a real run uses, then
exits without opening a connection. Nonzero status means a file is malformed.
Worth doing before a run because the loader enforces more than syntax: it also
rejects combinations that would produce a case which cannot fail, such as an
`abort` case carrying `expect_not` — a reset connection has no response, so the
assertion would pass against an empty buffer whatever the server did.

Catching that here costs nothing; catching it after a server boot costs a cycle,
and *not* catching it means a green test that asserts nothing.

**6. Build the prober and run:**

```sh
( cd t/harness/prober && ./build.sh )     # builds prober + json_test
PROBER_PROBE='mymod_probe probezone;' \
PROBER_PROBE_ZONE='mymod_ban_zone probezone:1m;' \
PROBER_MODULE=ngx_http_mymod_module.so \
PROBER_DIRECTIVE=mymod_probe \
t/harness/prober/run.sh nginx 1.31.3
```

`PROBER_PROBE` is what fills the `/__probe` location in the conf template;
see [Consumer contract](#consumer-contract) for when it is required.

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

### Proving the tests assert

`prober/test.sh` proves the self-tests **run**. `prober/mutate.sh` proves they
**assert**: it breaks the code on purpose, once per known behaviour, and requires
the named suite to go red each time.

```sh
prober/mutate.sh              # every mutation
prober/mutate.sh SO_LINGER    # only those matching a substring
```

A `SURVIVED` line means the suite passed with the code deliberately broken —
that behaviour is untested, whatever the coverage number says. It has found a
real gap on every pass so far, including a directive whose entire effect was
untested behind assertions that read as thorough.

Doing this by hand is where the danger is, and the script exists mostly to
remove three failure modes that each *look* like a caught mutation:

- **the mutation did not compile** — the build fails, the stale binary re-runs,
  the suite goes red anyway. The `-Werror` wall makes this common: zeroing a
  parameter's only use trips `-Werror=unused-parameter`, so `x * 0` is the safe
  mutation, not `0`.
- **the edit did not apply** — a pattern matching nothing leaves the code
  pristine, the suite passes, and that reads as `SURVIVED`. Anchors are literal
  strings and must match exactly once.
- **the wrong suite was run** — a transport mutation checked against the parser
  tests survives trivially.

Any of those is reported as `BROKEN`, never as a result, and fails the run.

## Stock rules

`rules/stock/` holds rule families that hold for **any** module, so a
consumer gets them without writing them. `PROBER_RULES` is word-split by
`run.sh`, so several space-separated globs compose:

```sh
PROBER_RULES="t/harness/rules/stock/*.rule t/prober/rules/*.rule" \
PROBER_PROBE='mymod_probe probezone;' \
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
| `slow-headers.rule` | A request line, a stall, then the headers — partial-header handling and header timeouts |
| `slowloris.rule` | The request dribbled out in small paced chunks |
| `abort.rule` | The client resets mid-request (RST); resources released when the peer vanishes |
| `half-close.rule` | The client half-closes (`SHUT_WR`) and is still answered |
| `abandoned-response.rule` | The client completes its request, then stops listening without erroring |
| `slow-reader.rule` | The client drains its socket slowly through a shrunken window (backpressure) |
| `close-deadline.rule` | The server closes the connection it promised to close, on time |

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
    nginx.conf    conf template, placeholders below  (default: $PROBER_CONF)
    *.rule        cases run by the prober            (default: $PROBER_RULES)
    env           sourced before boot: LD_PRELOAD, ulimit, PROBER_ALLOW_LOG
    driver.sh     replaces the prober call: signal choreography (see below)
    requires      gate; nonzero exit = scenario SKIPPED, not failed
    backend       fakesrv script; its presence starts a fake upstream
```

Every conf template — a scenario's `nginx.conf` or the single-run
`$PROBER_CONF` — is rendered through the same substitution pass before the
server sees it. Six placeholders are recognized, and nothing else is: a
template containing an unknown `@NAME@` reaches nginx with the literal text
intact, which `render_conf_test.sh` fails on rather than leaving to be
discovered as a parse error.

| Placeholder | Supplied by | Expands to |
|---|---|---|
| `@LOAD@` | harness | The `load_module` line for a dynamic build; empty when the module is linked statically (asan/coverage builds) |
| `@PORT@` | harness | `$PROBER_PORT` (default `18099`) |
| `@PREFIX@` | harness | The per-run `mktemp -d` prefix — `pid` and `error_log` must be written under it |
| `@PROBE@` | **consumer** (`PROBER_PROBE`) | The body of the `/__probe` location: the module's probe directive |
| `@PROBE_ZONE@` | **consumer** (`PROBER_PROBE_ZONE`) | An http-level declaration the probe directive needs, if any |
| `@BACKEND_PORT@` | harness (`PROBER_BACKEND_PORT`) | The ephemeral port the fake upstream bound; empty when the scenario ships no `backend` file, which is the normal case |

`@PROBE@` and `@PROBE_ZONE@` are the consumer's because the probe directive is
module-specific — the generic tree cannot name `shield_probe` any more than it
can name yours. A template that uses `@PROBE@` while `PROBER_PROBE` is unset
**bails at render** rather than substituting empty, because an empty probe
location falls through to `location /`, the prober parses the wrong body and
reports `malformed number` — a failure that points nowhere near its cause.
`PROBER_PROBE_ZONE` is genuinely optional: a probe directive needing no zone
leaves it unset and `@PROBE_ZONE@` renders empty.

```sh
PROBER_PROBE='mymod_probe probezone;' \
PROBER_PROBE_ZONE='mymod_ban_zone probezone:1m;' \
PROBER_MODULE=ngx_http_mymod_module.so \
PROBER_DIRECTIVE=mymod_probe \
prober/run-scenario.sh ./scenarios/conn-delta nginx 1.31.3
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
`PROBER_RESOLVED_PORT`, `PROBER_BACKEND_PORT` and `PROBER_BACKEND_JOURNAL`
(both empty when the scenario ships no `backend` file, so a driver may read
them under `set -u` without knowing whether it has an upstream).

A scenario that ships a `backend` file gets a fake upstream, started before
the conf is rendered — it binds an ephemeral port and `@BACKEND_PORT@`
substitutes what it bound, so the value does not exist any earlier. Teardown
takes the backend down before the server, so the module under test never sees
its upstream vanish while still being asked for something, and
`prober_backend_scrape` reports a backend that died mid-scenario as a finding
even when the error log is clean. `PROBER_BACKEND_ALLOW_EXIT` exempts a
scenario that kills it on purpose.

Two engine-level gates apply to every scenario, because each guards an
inference the harness depends on: `worker_processes 1` (the pid oracle) and
`daemon off;` (the engine tracks the master by `$!`; a daemonized server
orphans itself past teardown and holds the port into the next scenario). The
error-log scrape runs per scenario, `PROBER_ALLOW_LOG` and all.

All three entry points share the same engine (`prober/lib.sh`), so boot,
teardown and the log scrape cannot drift apart between them.

### The reference module (`t/module`)

The scenario tree needs a module to boot against: `prober_resolve` requires
`PROBER_MODULE` and `PROBER_DIRECTIVE`, which are the consuming module's to
supply. `t/module` is a minimal one so CI can run the tree without a consumer
— it registers neither probe hook, takes no shm zone, and its whole directive
is `test_ref_probe;`. A module registering no hooks still gets the entire
generic document (flavor, pid, connections, fds, cycle-pool accounting), which
is what every checked-in scenario asserts on.

It is not a template for writing a consumer: the hook API is what a real
module uses, and it is documented in `src/ngx_test_probe.h`. This one exists
only so the harness can be proven end to end.

```sh
./configure --with-compat --add-dynamic-module=t/module
make -j"$(nproc)"
mkdir -p .build/nginx-1.29.0 && cp -r objs .build/nginx-1.29.0/

PROBER_ROOT="$PWD" \
PROBER_MODULE=ngx_http_test_ref_module.so \
PROBER_DIRECTIVE=test_ref_probe \
PROBER_PROBE='test_ref_probe;' \
    prober/test-scenarios.sh nginx 1.29.0
```

`--without-http_rewrite_module` must NOT be passed: the scenario confs use
`return 200`, which is a rewrite-module directive.

### One scenario is skipped, on purpose

It ships a `requires` gate that reports why, so it shows as a TAP skip with a
reason rather than quietly not running:

- **`keepalive-bleed`** — needs `pipeline N` with per-response expects. The
  prober's read loop reads to EOF, so every rule must ask for
  `Connection: close`, and a rule that closes the connection is not testing
  keepalive.

It was unrunnable from the day it was written; nothing noticed until CI first
booted a server. (`multi-worker` was skipped for the same reason until the
`PROBER_ALLOW_MULTIWORKER` opt-in below let its `worker_processes 4` conf run
under the same-master pid oracle — see below.)

## Fake upstream (`prober/fakesrv`)

A scriptable fake redis/memcached backend, for testing modules that talk to an
upstream cache. It exists because a **real** daemon is the wrong instrument for
the cases that matter: it cannot be made to truncate a reply mid-`VALUE`, to
declare a length it then contradicts, to reset after eight bytes, or to close a
parked keepalive connection at the moment of a reload — and those are exactly
the paths where a module's error handling either releases its resources or
leaks them.

It also **reports what it saw**. A real daemon cannot tell you whether a
connection was reused; the JSONL journal can, which turns "the keepalive pool
works" from an assumption into a one-line assertion.

```sh
prober/fakesrv -script mc.backend -listen 127.0.0.1:0 \
               -portfile "$PROBER_PREFIX/backend.port" \
               -journal  "$PROBER_PREFIX/backend.jsonl"
```

`-listen …:0` binds an ephemeral port and writes the real one to `-portfile`
(atomically, before the first `accept()`, so a polling shell can never read it
half-written).

### Script format

Stanza style, mirroring `.rule`. The default with no faults is a **correct**
server backed by a real in-memory store:

```
proto   memcached
seed    hello  world
seed    empty  ""
fault   on=get:3     action=truncate    after=8
fault   on=get:*     action=lie_bytes   delta=+5
fault   on=set:1     action=rst
fault   on=connect:2 action=accept_close
fault   on=get:2     action=drip        bytes=1 ms=5
fault   on=idle      action=close_after ms=100
fault   on=get:4     action=raw         data=VALUE k 0 3\r\nAB\0\r\nEND\r\n
```

`seed <key> <value>` stores a value verbatim, with the same `\r \n \t \\ \" \0
\xNN` escapes the rest of the format uses. A bare `""` seeds a **zero-length**
value — legal memcached (`VALUE k 0 0\r\n\r\nEND\r\n`) and a classic
reply-framing off-by-one, since the payload is empty between two CRLFs. Only
that exact token is special: `"a"` keeps its quotes, and a `seed` with no value
at all stays fatal, because that form is far more often a typo than an
intention.

Faults are **overlays on correct behaviour**, keyed `(command-glob : occurrence)`.
That is the load-bearing design decision, and the obvious alternative was
rejected: a positional list of canned replies cannot express a keepalive test,
because the number of `get`s nginx will issue is precisely what such a test is
trying to discover — a reply list encodes the answer into the question.

`<nth>` is a 1-based occurrence counter (per command, per run) or `*` for every
occurrence. An exact match beats a `*` match, so a script can state a general
rule and except one occurrence from it. Two pseudo-commands cover what is not a
command: `connect:<nth>` fires as the nth connection is accepted, and `idle`
fires on a connection that has gone quiet.

| action | parameters | what it does |
|---|---|---|
| `truncate` | `after=<bytes>` | correct reply, cut after N bytes, then RST |
| `lie_bytes` | `delta=<signed>` | declared length disagrees with the payload |
| `rst` | — | TCP reset instead of a reply |
| `accept_close` | — | accept, then close without reading |
| `drip` | `bytes=<n> ms=<n>` | correct reply, N bytes at a time |
| `close_after` | `ms=<n>` | close this long after the connection goes idle |
| `raw` | `data=<bytes>` | send these exact bytes instead |
| `cursor_never_zero` | — | RESP `SCAN` that never terminates |

`raw` carries most of the adversarial surface — embedded NULs, oversize declared
lengths, a reply when none was due, `$-1` nil against a malformed near-miss. It
uses the same `\r \n \t \\ \" \0 \xNN` escapes as a rule file's `send`, through
the same lexer, so the two formats cannot drift on what a byte means.

An unknown `action=` is **fatal, never skipped**. A dropped fault leaves a
scenario exercising the happy path while its name and its TAP output both claim
otherwise — and a scenario that tests nothing passes very reliably.

### Journal

```
{"ev":"listen","port":41897}
{"ev":"accept","conn":1,"t_ms":12}
{"ev":"cmd","conn":1,"n":7,"cmd":"get","args":["hello"]}
{"ev":"close","conn":1,"by":"peer","cmds":5}
{"ev":"summary","accepts":1,"conns_max":1,"cmds":5}
```

The `summary` record is the point: `accepts==1 && cmds==5` proves the connection
was reused, `accepts==5` proves it was not. No amount of reading the module's
own logs settles that as directly.

### Verbs

The full memcached verb table is implemented so nothing draws an accidental
`ERROR` — but real *semantics* only for `get`/`set`/`delete`/`flush_all` plus
the RESP set a cache module sends; the rest return correct-shaped canned replies
(`VERSION 1.6.38-fake`, a fixed `STAT` block, `OK`).

**It is deliberately not a real cache.** The moment a scenario needs eviction or
expiry, it should point at a real daemon instead — a fake that grows toward
being a real redis is a second implementation to keep correct, and its bugs
become indistinguishable from the module's.

## Consumer contract

One nginx.conf requirement and a handful of environment variables must be
honored for the harness to run correctly:

**`PROBER_PROBE` / `PROBER_PROBE_ZONE` (required when the conf uses `@PROBE@`)**

The probe location's body is the consumer's, not the harness's — see the
placeholder table under [Scenarios](#scenarios) for the full rendering
contract. `PROBER_PROBE` carries the module's probe directive and
`PROBER_PROBE_ZONE` any http-level declaration it depends on:

```sh
PROBER_PROBE='mymod_probe probezone;' \
PROBER_PROBE_ZONE='mymod_ban_zone probezone:1m;' \
PROBER_MODULE=ngx_http_mymod_module.so \
PROBER_DIRECTIVE=mymod_probe \
prober/run.sh nginx 1.31.3
```

A conf using `@PROBE@` with `PROBER_PROBE` unset bails at render. Both values
are escaped before substitution, so a directive containing `&`, `\` or `#`
renders literally rather than corrupting the conf.

**`worker_processes 1` (required in consumer conf)**

The pid oracle — which asserts that the worker pid does not change across
consecutive probe requests — only holds with a single worker process. With
multiple workers, the same healthy server answers each request with a
different worker, changing the reported pid on every case and causing
universal test failure. Because the consumer supplies the nginx.conf, this
cannot be enforced by shipping a default configuration. `run.sh` parses the
rendered config file and exits with a bail-out before the first case if
`worker_processes` is not exactly `1` — unless the scenario opts in with
`PROBER_ALLOW_MULTIWORKER` (below).

**`PROBER_ALLOW_MULTIWORKER` (environment variable, optional)**

Set to `1` (in a scenario's `env` file) to lift the `worker_processes != 1`
bail above. It exists for the one scenario shape whose *point* is behaviour
across several workers: there, a healthy server answers consecutive probes from
different worker pids, so **every case must carry `pid_may_change`**, which
switches the oracle from "same worker" (pid) to "same master" (ppid). That
still catches the probe port being answered by a worker of a *different* master
(a rogue or leaked server), while tolerating the per-request worker rotation a
multi-worker server does by design. Setting this without `pid_may_change` on
every case reproduces the wall of false pid failures the bail exists to
prevent, so it is a per-scenario opt-in, never a run default. The `multi-worker`
scenario is the reference user.

**`PROBER_DAEMON_MODE` (environment variable, optional)**

Set to `on` (in a scenario's `env` file) to run the server with `daemon on;`
instead of the harness default `daemon off;`. It exists for exactly one
scenario shape: a **USR2 binary upgrade**. nginx drops the `NGX_CHANGEBIN`
signal when `getppid() == ngx_parent`, which always holds for a foregrounded
(`daemon off`) master whose parent is the harness's `&` launcher — so under the
default the upgrade is silently ignored, the master logs *"the changing binary
signal is ignored"*, and no new master ever forks. `daemon on;` lets the master
double-fork away from the launcher so the upgrade path is reachable.

Because a daemonized master is no longer `$!`, opting in also **requires the
conf to write its pidfile to `@PREFIX@/nginx.pid`**: boot then adopts the
master pid from that file, and teardown reads it (and `nginx.pid.oldbin`, where
a USR2 upgrade moves the retired master) rather than trusting `$!`. `check_conf`
bails if the opt-in is set without `daemon on;` or without that pidfile path.
A driver that upgrades the master mid-run does not need to thread the new pid
back to teardown — teardown re-reads the pidfile, so it always kills the live
generation. The `backend-usr2-keepalive` scenario is the reference user.

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
- **Field drift a rule does *not* name is guarded by `probe-schema.json`.** The
  loud failure above only fires for a field some rule references. One that is
  renamed, retyped or dropped while nothing references it stays invisible until
  someone writes a rule against it and reads the failure as a bug in their rule.
  `schema_test.c` checks both document variants against that file, and
  `schema_emitter_test.sh` checks the file against the format strings in
  `ngx_test_probe.c` — including the reverse direction, so a field the emitter
  gains without being declared is also red. Adding a member to the probe means
  adding it to the schema.
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
