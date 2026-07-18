/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * assert.h -- evaluation of `probe` and `delta` assertions against probe
 * documents.
 *
 * Split out of prober.c so it can be exercised without a server. This code IS
 * the verdict: everything else in the harness exists to put a document in front
 * of it. An evaluator that returns "pass" where it should return "fail" makes
 * every rule that depends on it untestable-by-construction, and the run still
 * reports green -- which is worse than having no rule, because the green is
 * believed.
 *
 * Both entry points return 1 on pass and 0 on fail, and on fail write a
 * human-readable reason into `why`. There is no third outcome: a path that
 * cannot be evaluated (absent, wrong type, unusable literal) is a failure, not
 * a skip, because a skip would be indistinguishable from a pass in TAP.
 */

#ifndef NGX_TEST_HARNESS_ASSERT_H
#define NGX_TEST_HARNESS_ASSERT_H

#include <stddef.h>

#include "json.h"
#include "rules.h"

/* Compare two numbers with a rule-file operator. The operator must already
 * have been accepted by the rule parser; an unknown one here is a bug in the
 * harness rather than in the rule file, and is fatal. */
int compare_number(double have, const char *op, double want);

/*
 * Strip surrounding double quotes from a rule literal into `scratch`, or
 * return `lit` unchanged when it is not quoted.
 *
 * Returns NULL when a quoted literal does not fit in `scratch`. That is
 * reported by the caller as an assertion failure rather than being fatal: an
 * over-long literal is one bad line in one rule file, and killing the process
 * for it would truncate the TAP stream and take every later case down with it.
 */
const char *unquote(const char *lit, char *scratch, size_t scratchlen);

/* Evaluate `<path> <op> <literal>` against a single probe document. */
int eval_probe(const json_value *doc, const probe_assert *pa, char *why,
    size_t whylen);

/* Evaluate `(after - before) <op> <literal>` across two probe documents. */
int eval_delta(const json_value *before, const json_value *after,
    const probe_assert *pa, char *why, size_t whylen);

#endif /* NGX_TEST_HARNESS_ASSERT_H */
