/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * util.h -- the three helpers shared by the rule parser and the assertion
 * evaluator.
 */

#ifndef NGX_TEST_HARNESS_UTIL_H
#define NGX_TEST_HARNESS_UTIL_H

#include <stddef.h>

/*
 * Fatal, with a "prober: " prefix on stderr and exit status 2.
 *
 * _Noreturn is load-bearing rather than decoration: without it clang cannot see
 * that the default arm of the escape switch in the rule parser never falls
 * through, and rejects the function under -Wsometimes-uninitialized.
 *
 * Status 2 and not 1 so a rule-file or usage error is distinguishable from
 * "the tests ran and some failed", which is 1.
 */
_Noreturn void die(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

/* strdup(), or die trying. */
char *xstrdup(const char *s);

/* Trim leading and trailing whitespace in place; returns the new start. */
char *trim(char *s);

#endif /* NGX_TEST_HARNESS_UTIL_H */
