/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_test_probe.c -- in-worker test probe renderer (CI only).
 *
 * See ngx_test_probe.h for what this is and why it is split from the HTTP
 * module that exposes it.
 *
 * The hook registry and the fault_slab= parser live in ngx_test_probe_arm.c.
 * Both files are part of the same unit and consumers build both; they are
 * separate only because the parser depends on nothing but the query bytes,
 * which lets it be tested against a 50-line shim instead of a configured
 * server. What is rendered here cannot be: it reads ngx_cycle, the slab pool
 * and /proc/self/fd, so it is checked by compiling against real nginx and real
 * angie headers in CI, and by the live prober run.
 */

#include "ngx_test_probe.h"

#ifdef NGX_TEST_HARNESS

/* offsetof() for the ABI pins below only; the disabled build must not gain a
 * dependency this translation unit did not already have. */
#include <stddef.h>


extern ngx_test_probe_hooks_t  ngx_test_probe_hooks;


/*
 * ngx_test_probe_pool_stats() walks the cycle pool's block chain and treats
 * the head block as carrying the full ngx_pool_t header while every later
 * block carries only ngx_pool_data_t -- see the comment there. That split
 * only produces the right `start` pointer if ngx_pool_data_t is genuinely the
 * FIRST member of ngx_pool_t, i.e. at offset 0: the head block's ngx_pool_t
 * and a later block's ngx_pool_data_t must be reachable through the same
 * address for `p->d.next` to walk the chain uniformly regardless of which
 * kind of header is actually there. If a future nginx/angie reorders
 * ngx_pool_s to put `d` anywhere but first, this cast silently walks into the
 * wrong bytes and reports a fabricated pool_used figure instead of failing --
 * exactly the kind of wrong-but-plausible number this probe exists to avoid
 * producing.
 */
NGX_TEST_PROBE_ABI_PIN(offsetof(ngx_pool_t, d) == 0,
    "ngx_pool_t layout changed: ngx_pool_data_t (\"d\") is no longer the "
    "first member -- ngx_test_probe_pool_stats()'s per-block start-pointer "
    "arithmetic now reads the wrong offset in every block after the head");

/*
 * The same walk also assumes a later block's header really is exactly
 * sizeof(ngx_pool_data_t) bytes, distinct from the head block's
 * sizeof(ngx_pool_t) -- if those two ever collapsed to the same size (e.g.
 * ngx_pool_t shrank to hold nothing but ngx_pool_data_t) the `p == pool`
 * branch would stop mattering, which is harmless, but the reverse -- the
 * struct growing new members ahead of `d` -- is caught by the offset pin
 * above, not this one. This pin exists to catch the one drift that offset
 * pin cannot: ngx_pool_data_t itself growing or shrinking without ngx_pool_t
 * following, which would desync every block after the first from where its
 * usable memory actually starts.
 */
NGX_TEST_PROBE_ABI_PIN(sizeof(ngx_pool_data_t) < sizeof(ngx_pool_t),
    "ngx_pool_t no longer strictly larger than ngx_pool_data_t -- "
    "ngx_test_probe_pool_stats() assumes the head block's header "
    "(sizeof(ngx_pool_t)) and every later block's header "
    "(sizeof(ngx_pool_data_t)) are different sizes; if they ever match, "
    "verify the per-block start-pointer arithmetic by hand before trusting "
    "this pin's silence");


/*
 * Open file descriptors held by THIS worker.
 *
 * The delta of this across a request is the fd-leak signal: a connection,
 * upstream socket or temp file the module forgot to close stays visible here
 * long after the response body is on the wire, where the response itself shows
 * nothing. Linux-only by construction (/proc/self/fd); elsewhere the field is
 * reported as -1 so a rule asserting on it fails loudly rather than silently
 * comparing against a fabricated zero.
 */
static ngx_int_t
ngx_test_probe_fd_count(void)
{
#if (NGX_LINUX)
    ngx_dir_t   dir;
    ngx_err_t   err;
    ngx_int_t   n;
    ngx_str_t   name = ngx_string("/proc/self/fd");

    if (ngx_open_dir(&name, &dir) == NGX_ERROR) {
        return -1;
    }

    n = 0;
    err = 0;

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) == NGX_ERROR) {
            /* End of directory leaves errno at the 0 set above; anything else
             * is a real read failure, and a partial count would understate the
             * fd total -- i.e. hide the very leak this exists to catch. */
            err = ngx_errno;
            break;
        }

        if (ngx_de_name(&dir)[0] == '.') {
            continue;                     /* "." and ".." */
        }

        n++;
    }

    (void) ngx_close_dir(&dir);

    if (err != 0) {
        return -1;
    }

    /* The directory handle was itself one of the entries it just listed, and
     * it is closed again by the time the caller sees this number. */
    return n > 0 ? n - 1 : n;
#else
    return -1;
#endif
}


/*
 * Bytes handed out from the CYCLE pool, plus its block and large-alloc counts.
 *
 * Request pools are freed wholesale at request end, so a per-request pool leak
 * is invisible from outside -- which is exactly why this measures the cycle
 * pool instead. Nothing in normal request handling may allocate there: it lives
 * as long as the worker does, so an allocation on it per request is an
 * unbounded leak. The delta across a request is therefore expected to be 0,
 * and any other value is a bug even though ASan and valgrind both stay quiet
 * (the memory is still reachable and still freed at exit).
 */
static void
ngx_test_probe_pool_stats(ngx_pool_t *pool, size_t *used, ngx_uint_t *blocks,
    ngx_uint_t *large)
{
    u_char            *start;
    ngx_pool_t        *p;
    ngx_pool_large_t  *l;

    *used = 0;
    *blocks = 0;
    *large = 0;

    if (pool == NULL) {
        return;
    }

    /* Only the first block carries the full ngx_pool_t header; the blocks
     * chained after it carry ngx_pool_data_t alone. */
    for (p = pool; p != NULL; p = p->d.next) {
        start = (u_char *) p + ((p == pool) ? sizeof(ngx_pool_t)
                                            : sizeof(ngx_pool_data_t));
        (*blocks)++;
        *used += (size_t) (p->d.last - start);
    }

    /* Large allocations hang off the head pool regardless of which block was
     * current when ngx_palloc_large() ran. */
    for (l = pool->large; l != NULL; l = l->next) {
        if (l->alloc != NULL) {
            (*large)++;
        }
    }
}


u_char *
ngx_test_probe_json(u_char *buf, u_char *last, ngx_shm_zone_t *zone)
{
    size_t           pool_used;
    u_char          *p;
    ngx_int_t        fds;
    ngx_uint_t       pages_free, present, pool_blocks, pool_large;
    ngx_slab_pool_t *shpool;

    pages_free = 0;
    present = 0;

    fds = ngx_test_probe_fd_count();
    ngx_test_probe_pool_stats(ngx_cycle->pool, &pool_used, &pool_blocks,
                              &pool_large);

    /*
     * Worker identity and connection accounting.
     *
     * "ppid" is ngx_parent, which ngx_spawn_process() sets in the PARENT just
     * before forking, so a worker reads the master's pid from it. It is the
     * oracle for `pid_may_change`: a reload legitimately replaces the worker,
     * and the surviving invariant is not "same pid" but "still a child of the
     * same master". Deliberately NOT getppid(): once a master exits, a worker
     * is reparented to init and getppid() would report a pid unrelated to
     * nginx -- which is precisely the crash the assertion has to catch.
     *
     * connection_n / free_connection_n are plain ngx_cycle fields present in
     * both nginx and angie. Deliberately NOT ngx_stat_active and friends: those
     * exist only under NGX_STAT_STUB, so reading them would silently couple the
     * harness to whether stub_status was configured into the build.
     */
    p = ngx_slprintf(buf, last,
                     "{\"flavor\":\"%s\","
                     "\"flavor_version\":\"%s\","
                     "\"pid\":%P,"
                     "\"ppid\":%P,"
                     "\"page_size\":%uz,"
                     "\"connections\":{\"total\":%ui,\"free\":%ui},"
                     "\"fds\":%i,"
                     "\"pool\":{\"cycle_used\":%uz,\"cycle_blocks\":%ui,"
                     "\"cycle_large\":%ui}",
                     (u_char *) NGX_TEST_PROBE_FLAVOR,
                     (u_char *) NGX_TEST_PROBE_FLAVOR_VER,
                     ngx_pid,
                     ngx_parent,
                     (size_t) ngx_pagesize,
                     (ngx_uint_t) ngx_cycle->connection_n,
                     (ngx_uint_t) ngx_cycle->free_connection_n,
                     fds,
                     pool_used,
                     pool_blocks,
                     pool_large);

    if (zone == NULL) {
        return ngx_slprintf(p, last, ",\"zone\":{\"present\":false}}");
    }

    /*
     * shm.addr is filled when the master allocates the zone, before any worker
     * forks, and IS the slab pool: every nginx shm zone starts with an
     * ngx_slab_pool_t. A probe that races a reload can legitimately see a zone
     * whose memory is not mapped yet -- report that instead of dereferencing
     * it. Reading pfree needs no module knowledge, which is why zone occupancy
     * works for any module without a hook.
     *
     * Deliberately NOT given an offsetof() pin like the pool-block walk above:
     * "the slab pool starts at offset 0 of shm.addr" is not a struct-layout
     * fact this translation unit can observe from either side. It is nginx's
     * shared-memory allocator (ngx_shm_alloc + ngx_init_zone_pool, outside
     * this file entirely) that places the ngx_slab_pool_t header at the front
     * of the segment it hands back; there is no second struct here whose
     * member offset could be compared against it, so any assert we could
     * write would just restate the cast and pass by construction rather than
     * catch drift. If that placement ever changes, mutex and pfree accesses
     * below read arbitrary bytes as an ngx_shmtx_t and an ngx_uint_t -- this
     * is real UB risk, it is just not one offsetof() can pin from this side;
     * the probe-compiles CI job (real nginx/angie headers) is what actually
     * guards it, same as the compiler already guards `mutex`/`pfree` existing
     * on ngx_slab_pool_t by name.
     */
    shpool = (ngx_slab_pool_t *) zone->shm.addr;

    if (shpool != NULL) {
        present = 1;

        ngx_shmtx_lock(&shpool->mutex);

        /* pfree is the free-page count the slab allocator maintains
         * unconditionally. pool->stats[] is the richer source but is only
         * populated under NGX_DEBUG_MALLOC-style builds, so it is not a
         * portable signal for a harness that must run on release-ish CI
         * builds of both nginx and angie. */
        pages_free = shpool->pfree;

        ngx_shmtx_unlock(&shpool->mutex);
    }

    p = ngx_slprintf(p, last,
                     ",\"zone\":{"
                     "\"present\":%s,"
                     "\"name\":\"%V\","
                     "\"size\":%uz,"
                     "\"slab_pages_free\":%ui",
                     (u_char *) (present ? "true" : "false"),
                     &zone->shm.name,
                     (size_t) zone->shm.size,
                     pages_free);

    /*
     * Module-specific members go inside the zone object, so a consuming
     * module's rules can assert on "zone.nodes" alongside the generic
     * "zone.slab_pages_free" without knowing which side rendered which.
     */
    if (present && ngx_test_probe_hooks.zone_render != NULL) {
        p = ngx_test_probe_hooks.zone_render(p, last, zone);
    }

    return ngx_slprintf(p, last, "}}");
}

#else

/* ISO C forbids an empty translation unit, and angie's configure adds -Werror,
 * so the disabled build needs a declaration to stand on. */
typedef int ngx_test_probe_not_built_t;

#endif /* NGX_TEST_HARNESS */
