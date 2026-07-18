/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_test_probe_arm.c -- hook registry, and the fault_slab= query parser.
 *
 * Split from the renderer because this half depends on nothing except the
 * query bytes: no ngx_cycle, no slab pool, no /proc. That makes it reachable
 * from a direct-call unit test built against a small shim, which matters
 * because it is a parser of attacker-shaped text -- the boundary rule, the
 * malformed-input contract and the digit bound are all things that are easy to
 * get subtly wrong and impossible to notice from a passing rule file.
 *
 * See ngx_test_probe.h.
 */

#include "ngx_test_probe.h"

#ifdef NGX_TEST_HARNESS


/* Shared with the renderer in ngx_test_probe.c, which reads zone_render from
 * it. Not static for that reason, and not exposed in the header either: it is
 * internal to this pair of files, not part of the consumer-facing API. */
ngx_test_probe_hooks_t  ngx_test_probe_hooks;


void
ngx_test_probe_register(const ngx_test_probe_hooks_t *hooks)
{
    if (hooks == NULL) {
        ngx_memzero(&ngx_test_probe_hooks, sizeof(ngx_test_probe_hooks_t));
        return;
    }

    ngx_test_probe_hooks = *hooks;
}


ngx_int_t
ngx_test_probe_arm(ngx_shm_zone_t *zone, ngx_str_t *args)
{
    static const u_char  key[] = "fault_slab=";
    const size_t         keylen = sizeof(key) - 1;

    int                  negative;
    ngx_uint_t           digits;
    u_char              *p, *end, *v;
    ngx_int_t            value;

    if (ngx_test_probe_hooks.fault_set == NULL) {
        return NGX_DECLINED;
    }

    if (zone == NULL || args == NULL || args->len < keylen) {
        return NGX_DECLINED;
    }

    end = args->data + args->len;

    /*
     * Match the key as a whole query argument, not as a substring: it must
     * start the query or follow an '&', or "not_fault_slab=1" would arm the
     * injector through a parameter nobody wrote.
     */
    for (p = args->data; (size_t) (end - p) >= keylen; p++) {
        if (ngx_strncmp(p, key, keylen) != 0) {
            continue;
        }

        if (p == args->data || p[-1] == '&') {
            break;
        }
    }

    if ((size_t) (end - p) < keylen) {
        return NGX_DECLINED;
    }

    v = p + keylen;
    negative = 0;

    if (v < end && *v == '-') {
        negative = 1;
        v++;
    }

    if (v >= end || *v < '0' || *v > '9') {
        return NGX_DECLINED;
    }

    value = 0;
    digits = 0;

    while (v < end && *v >= '0' && *v <= '9') {
        /*
         * Bounded before the multiply, not after. The nth-allocation counter
         * this feeds is small by nature -- rules arm the 1st or 2nd slab
         * allocation -- so nothing legitimate reaches even four digits, while
         * an unbounded accumulate overflows ngx_int_t on a long enough digit
         * run, which is undefined behaviour and would land as an arbitrary
         * (possibly negative) fault index rather than as the refusal the
         * caller expects for garbage.
         */
        if (++digits > NGX_TEST_PROBE_FAULT_MAX_DIGITS) {
            return NGX_DECLINED;
        }

        value = value * 10 + (*v - '0');
        v++;
    }

    /* The value has to end where the argument ends. "fault_slab=1junk" is
     * malformed, and the contract for malformed input is NGX_DECLINED rather
     * than a best guess at what the caller meant. */
    if (v < end && *v != '&') {
        return NGX_DECLINED;
    }

    if (negative) {
        value = -value;
    }

    return ngx_test_probe_hooks.fault_set(zone, value);
}

#else

/* ISO C forbids an empty translation unit, and angie's configure adds -Werror,
 * so the disabled build needs a declaration to stand on. */
typedef int ngx_test_probe_arm_not_built_t;

#endif /* NGX_TEST_HARNESS */
