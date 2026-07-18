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
 *
 * The GNU noreturn attribute is spelled out ALONGSIDE C11 _Noreturn, which is
 * redundant to a compiler and is not redundant to cppcheck: it does not model
 * _Noreturn, so every `if (x == NULL) { die(...); }` guard in this codebase
 * reads to it as a fall-through into a null dereference. That produced four
 * null-pointer findings, all false, at sites where the guard is correct.
 * Suppressing them by id would have blinded the checker to the genuine class
 * as well, so the declaration is made legible to the tool instead. Verified
 * against cppcheck 2.17.1: with only _Noreturn it warns, with the attribute
 * it does not.
 */
_Noreturn void die(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)))
    __attribute__((noreturn));

/* strdup(), or die trying. */
char *xstrdup(const char *s);

/* Trim leading and trailing whitespace in place; returns the new start. */
char *trim(char *s);

/*
 * strtol() where the WHOLE token has to be the number, or die with `what` in
 * the message.
 *
 * This exists because atoi() cannot report a conversion error: it returns 0 for
 * "junk" exactly as it does for "0". On a command-line flag that is a silent
 * wrong answer -- `-p http` became port 0 and `-t junk` became a 0 ms timeout,
 * which times out every request and reds the entire suite while pointing
 * nowhere near the actual mistake. The rule parser already rejects partial
 * numbers for the same reason (see the "10junk" note in rules.c); this is that
 * check, shared, instead of open-coded a fourth time.
 */
long xstrtol(const char *s, const char *what);

#endif /* NGX_TEST_HARNESS_UTIL_H */
