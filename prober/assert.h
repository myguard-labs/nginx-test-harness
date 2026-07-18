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

/*
 * Verify the worker that answered the after-snapshot is the one that answered
 * the before-snapshot.
 *
 * This is not driven by a rule directive: it applies to every case, because a
 * worker that segfaults mid-request is respawned by the master, and the retry
 * the client never sees can still produce the status and body the rule asked
 * for. The case then reports ok while the module under test crashed. A changed
 * pid is that crash, and it is visible with no sanitizer and no module C.
 *
 * Unlike a delta, an absent or non-numeric "pid" is a failure rather than
 * something to compare: the pid is rendered unconditionally by the generic
 * half of the probe, so its absence means the document is not the document
 * this oracle thinks it is, and silently skipping would turn the check off
 * everywhere at once.
 *
 * REQUIRES worker_processes 1. "The worker" is only a meaningful subject with
 * one of them: several live workers answer consecutive probe requests in turn,
 * so the pid changes on a server that is perfectly healthy and every case
 * fails. The conf belongs to the consumer, so this cannot be enforced here --
 * run.sh checks the rendered file and bails before the first case instead.
 */
int eval_pid_stable(const json_value *before, const json_value *after,
    char *why, size_t whylen);

#endif /* NGX_TEST_HARNESS_ASSERT_H */
