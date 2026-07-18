# nginx-test-harness

Functional + leak testing for nginx and angie modules, in C, with no Perl and no
version banner sniffing.

Two halves:

- **`src/ngx_test_probe.{c,h}`** — an in-worker probe compiled into the module
  under test. Renders worker and shm-zone state as JSON so a test can assert on
  things the HTTP response never reveals.
- **`prober/`** — a standalone C prober. Rule files, raw sockets, a strict JSON
  reader, TAP output. Knows nothing about any particular module.

## Why

Three gaps this closes, in the order they hurt:

**Leaks that sanitizers cannot see.** A leaked fd is not a memory error, so ASan
and valgrind say nothing. A per-request allocation on a request pool is freed
wholesale at request end, so it is invisible from outside — which is why the
probe measures the **cycle** pool, where nothing in normal request handling may
allocate at all, and any nonzero delta is unbounded growth for the life of the
worker.

**angie has no functional coverage.** Stock `Test::Nginx::Socket` probes `-V` and
requires `nginx version: ...`; angie answers `Angie version: Angie/1.12.0` and
the suite bails before the first test. The prober reads no banner, so the same
rule files run against both.

**Allocation-failure paths are untested.** `malloc` does not fail in CI, so the
branches that handle a full slab or a failed `ngx_palloc` only execute on a box
under real pressure. The probe can arm a fault injector at those sites.

## Using it in a module

Add the harness as a submodule, compile `src/ngx_test_probe.c` and
`src/ngx_test_probe_arm.c` alongside your module when the harness is enabled,
and register what the probe cannot know generically:

```c
static u_char *
my_zone_render(u_char *buf, u_char *last, ngx_shm_zone_t *zone)
{
    /* appends to the "zone" object -- leading comma, no closing brace */
    return ngx_slprintf(buf, last, ",\"nodes\":%ui", my_count(zone));
}

static const ngx_test_probe_hooks_t  my_hooks = {
    .zone_render = my_zone_render,
    .fault_set   = my_fault_set,
};

ngx_test_probe_register(&my_hooks);
```

Both hooks are **optional**. Registering nothing still gets you the whole
generic document — flavor, pid, connections, `fds`, cycle-pool stats, and the
zone's name, size and slab page accounting — which is enough for fd and memory
leak assertions **without a line of module-specific C**. Slab occupancy works
for any zone because every nginx shm zone begins with an `ngx_slab_pool_t`.

You supply the HTTP surface (a directive and a content handler that calls
`ngx_test_probe_json()`), because an nginx module cannot inherit another
module's command table. That is roughly 60 lines, all of it behind
`#ifdef NGX_TEST_HARNESS`.

### Never ship it

The whole feature compiles out unless `NGX_TEST_HARNESS` is defined, and it must
stay that way in packaged builds: the probe walks queues under the slab mutex,
scans `/proc`, and exposes internal state unauthenticated.

## Rule files

```
name    a passed-through request leaks no fd and no cycle-pool memory
from    127.0.0.20
send    GET /unguarded HTTP/1.1\r\n
send    Host: prober\r\nConnection: close\r\n\r\n
expect  status=502
delta   fds == 0
delta   pool.cycle_used == 0
```

`probe` asserts on a single snapshot, `delta` on the change across the case.
`from` binds the source address — load-bearing for anything keyed on the peer,
since without varying it a per-IP fault never fires and the case passes for the
wrong reason.

## Running

```sh
PROBER_MODULE=ngx_http_mymod_module.so \
PROBER_DIRECTIVE=mymod_probe \
prober/run.sh nginx 1.31.3
```

`run.sh` gates on three things before a single case runs, because each one
produces a green run that proves nothing:

1. the prober binary is not older than its sources (it does not build them);
2. the JSON reader passes its own self-tests — it is the **oracle** every
   assertion runs through, so a lax reader makes the whole suite unable to fail;
3. the module actually carries the probe directive, decided by inspecting the
   binary rather than by whether a `.so` happens to exist.

## Consumer contract

One nginx.conf requirement and one environment variable must be honored for the
harness to run correctly:

**`worker_processes 1` (required in consumer conf)**

The pid oracle — which asserts that the worker pid does not change across
consecutive probe requests — only holds with a single worker process. With
multiple workers, the same healthy server answers each request with a different
worker, changing the reported pid on every case and causing universal test
failure. Because the consumer supplies the nginx.conf, this cannot be enforced by
shipping a default configuration. `run.sh` parses the rendered config file and
exits with a bail-out before the first case if `worker_processes` is not exactly `1`.

**`PROBER_ALLOW_LOG` (environment variable, optional)**

By default, `run.sh` treats any `[alert]`, `[crit]`, or `[emerg]` line in the
error log as a test failure — because a worker that crashes, finalizes a request
twice, or reuses a busy buffer logs at one of these levels, then carries on
serving. Without this gate, the suite passes while the bug ships.

However, fault-injection tests intentionally provoke failures to exercise
out-of-memory and allocation-failure paths. These tests arm the fault injector to
exhaustion, which nginx logs at `[crit]`, and the test must pass despite the
error. Set `PROBER_ALLOW_LOG` to an extended regex matching the expected error
line(s). Each matching line is reported in the test output but not counted as a
failure. The regex is matched per line against the full error log scrape, so a
pattern like `"no memory for"` exempts that specific condition while leaving
segfaults and other unexpected errors fatal.

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

## See also

- [nginx-http-shield-module](https://github.com/myguard-labs/nginx-http-shield-module)
  — first consumer; its `t/prober/` rules are a worked example.
