/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * assert_test.c -- TAP self-test for the assertion evaluators.
 *
 * These two functions ARE the verdict. Everything else in the harness exists to
 * put a document in front of them: the prober sends the request, http.c reads
 * the bytes, json.c turns them into values, and then eval_probe() and
 * eval_delta() decide whether a case passed.
 *
 * Which makes one failure mode dominant, and it is not "reports a failure that
 * is not real". It is the opposite: an evaluator that returns pass where it
 * should return fail makes every rule depending on it untestable by
 * construction, and the run still prints ok. Nobody investigates an ok. So the
 * bulk of what follows checks that assertions which CANNOT be meaningfully
 * evaluated -- absent paths, type mismatches, unusable literals, an unavailable
 * fd count -- come back as failures rather than as quiet passes.
 *
 * The `fds == -1` case is the sharpest example and has its own guard in
 * eval_delta(): when the probe cannot read /proc/self/fd it reports -1, both
 * snapshots carry -1, and the subtraction cancels them to a delta of 0. Every
 * `delta fds == 0` rule in every consuming module would pass while measuring
 * nothing at all.
 */

#include "assert.h"
#include "json.h"
#include "rules.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bumped by hand: a test that vanishes should show up as a plan mismatch
 * rather than as a smaller green run. */
#define PLANNED  64

static int  tests_run = 0;
static int  failures = 0;


static void
ok(int cond, const char *name)
{
    tests_run++;

    printf("%sok %d - %s\n", cond ? "" : "not ", tests_run, name);

    if (!cond) {
        failures++;
    }
}


/*
 * Every helper below asserts on `why` as well as on the verdict.
 *
 * A failure whose reason is empty is nearly as bad as a wrong verdict: the
 * prober prints it as a bare TAP comment, and whoever is looking at a red run
 * at that point has the response, the rule and no idea which of them is wrong.
 */
static void
check(int got, int want, const char *why, const char *name)
{
    int good = (got == want);

    if (good && !want && why[0] == '\0') {
        printf("# %s: failed without saying why\n", name);
        good = 0;
    }

    if (!good) {
        printf("# %s: verdict %d, want %d (why: \"%s\")\n",
               name, got, want, why);
    }

    ok(good, name);
}


static void
pid_is(const char *before_text, const char *after_text, int want,
       const char *name)
{
    char        why[512] = "";
    json_value *before = json_parse(before_text, NULL);
    json_value *after = json_parse(after_text, NULL);
    int         got;

    if (before == NULL || after == NULL) {
        printf("# %s: fixture does not parse\n", name);
        ok(0, name);
        json_free(before);
        json_free(after);
        return;
    }

    got = eval_pid_stable(before, after, why, sizeof(why));

    check(got, want, why, name);

    json_free(before);
    json_free(after);
}


static void
probe_is(const char *doc_text, const char *path, const char *op,
         const char *literal, int want, const char *name)
{
    char          why[512] = "";
    json_value   *doc = json_parse(doc_text, NULL);
    probe_assert  pa;
    int           got;

    if (doc == NULL) {
        printf("# %s: fixture does not parse: %s\n", name, doc_text);
        ok(0, name);
        return;
    }

    /* Build the struct the way rules.c does -- owned copies -- rather than
     * casting away const on the string-literal fixtures. probe_assert holds
     * char* because the parser hands it heap strings it later frees; borrowing
     * literals into it would misrepresent that ownership even though the
     * evaluator never writes through the pointers. */
    pa.path = xstrdup(path);
    pa.op = xstrdup(op);
    pa.literal = xstrdup(literal);

    got = eval_probe(doc, &pa, why, sizeof(why));

    check(got, want, why, name);
    free(pa.path);
    free(pa.op);
    free(pa.literal);
    json_free(doc);
}


static void
delta_is(const char *before_text, const char *after_text, const char *path,
         const char *op, const char *literal, int want, const char *name)
{
    char          why[512] = "";
    json_value   *before = json_parse(before_text, NULL);
    json_value   *after = json_parse(after_text, NULL);
    probe_assert  pa;
    int           got;

    if (before == NULL || after == NULL) {
        printf("# %s: fixture does not parse\n", name);
        ok(0, name);
        json_free(before);
        json_free(after);
        return;
    }

    pa.path = xstrdup(path);
    pa.op = xstrdup(op);
    pa.literal = xstrdup(literal);

    got = eval_delta(before, after, &pa, why, sizeof(why));

    check(got, want, why, name);
    free(pa.path);
    free(pa.op);
    free(pa.literal);
    json_free(before);
    json_free(after);
}


int
main(void)
{
    /* The shape ngx_test_probe_json() actually renders. */
    static const char doc[] =
        "{\"flavor\":\"nginx\",\"flavor_version\":\"1.29.0\",\"pid\":1234,"
        "\"page_size\":4096,\"connections\":{\"total\":512,\"free\":511},"
        "\"fds\":9,\"pool\":{\"cycle_used\":2048,\"cycle_blocks\":1,"
        "\"cycle_large\":0},"
        "\"zone\":{\"present\":true,\"name\":\"demo\",\"size\":1048576,"
        "\"slab_pages_free\":248,\"nodes\":2}}";

    printf("1..%d\n", PLANNED);

    /* ---- eval_probe: numbers ------------------------------------------ */

    probe_is(doc, "zone.nodes", "==", "2", 1, "a number equal to itself");
    probe_is(doc, "zone.nodes", "==", "3", 0, "a number not equal");
    probe_is(doc, "zone.nodes", "!=", "3", 1, "!= on a number");
    probe_is(doc, "zone.nodes", "<", "3", 1, "< on a number");
    probe_is(doc, "zone.nodes", "<", "2", 0, "< is strict");
    probe_is(doc, "zone.nodes", "<=", "2", 1, "<= includes equality");
    probe_is(doc, "zone.nodes", ">", "1", 1, "> on a number");
    probe_is(doc, "zone.nodes", ">", "2", 0, "> is strict");
    probe_is(doc, "zone.nodes", ">=", "2", 1, ">= includes equality");
    probe_is(doc, "pool.cycle_large", "==", "0", 1, "a zero compares equal");
    probe_is(doc, "connections.free", "==", "511", 1, "a two-level path");

    /* ---- eval_probe: strings ------------------------------------------ */

    probe_is(doc, "flavor", "==", "\"nginx\"", 1, "a quoted string matches");
    probe_is(doc, "flavor", "==", "nginx", 1, "an unquoted string matches too");
    probe_is(doc, "flavor", "==", "\"angie\"", 0, "the wrong string fails");
    probe_is(doc, "flavor", "!=", "\"angie\"", 1, "!= on a string");
    probe_is(doc, "flavor", "!=", "\"nginx\"", 0, "!= against the actual value");
    probe_is(doc, "flavor_version", "~", "1.29", 1, "~ is a substring test");
    probe_is(doc, "flavor_version", "~", "9.9", 0, "~ that does not match");
    probe_is(doc, "flavor", "~", "\"ngin\"", 1, "~ unquotes its literal");

    /*
     * An ordering operator on a string is refused rather than being answered
     * with strcmp(). "1.10" < "1.9" is true lexically and false as a version,
     * and a rule that appears to work while meaning something else is the
     * failure mode this whole file exists to prevent.
     */
    probe_is(doc, "flavor", "<", "\"z\"", 0, "< on a string is refused");
    probe_is(doc, "flavor", ">=", "\"a\"", 0, ">= on a string is refused");

    /* ---- eval_probe: booleans ----------------------------------------- */

    probe_is(doc, "zone.present", "==", "true", 1, "a true boolean");
    probe_is(doc, "zone.present", "==", "false", 0, "true is not false");
    probe_is(doc, "zone.present", "!=", "false", 1, "!= on a boolean");
    probe_is(doc, "zone.present", "!=", "true", 0, "!= against the actual bool");
    probe_is(doc, "zone.present", "==", "1", 0,
             "a boolean is not comparable to 1");
    probe_is(doc, "zone.present", "==", "\"true\"", 1,
             "a quoted true is unquoted first");
    probe_is(doc, "zone.present", "<", "true", 0,
             "< on a boolean is refused");

    /* ---- eval_probe: the ways an assertion must NOT quietly pass ------- */

    probe_is(doc, "zone.absent", "==", "1", 0, "an absent path fails");
    probe_is(doc, "absent.entirely", "==", "1", 0,
             "an absent parent fails");
    probe_is(doc, "zone.nodes", "==", "two", 0,
             "a non-numeric literal against a number fails");
    probe_is(doc, "zone.nodes", "==", "2x", 0,
             "a numeric literal with trailing junk fails");
    probe_is(doc, "zone.nodes", "==", "", 0,
             "an empty literal against a number fails");
    probe_is(doc, "zone", "==", "1", 0,
             "an object cannot be compared");
    probe_is("{\"a\":[1,2]}", "a", "==", "1", 0,
             "an array cannot be compared");
    probe_is("{\"a\":null}", "a", "==", "null", 0,
             "null cannot be compared");
    probe_is(doc, "", "==", "1", 0, "an empty path fails");

    /*
     * A quoted literal longer than the evaluator's scratch buffer used to be
     * fatal. One bad line in one rule file must not take the rest of the run
     * with it, so it is now an ordinary failure -- with a reason.
     */
    {
        char big[700];

        memset(big, 'x', sizeof(big));
        big[0] = '"';
        big[sizeof(big) - 2] = '"';
        big[sizeof(big) - 1] = '\0';

        probe_is(doc, "flavor", "==", big, 0,
                 "an over-long literal fails instead of killing the run");
    }

    /* ---- eval_delta ---------------------------------------------------- */

    delta_is(doc, doc, "fds", "==", "0", 1, "an unchanged fd count");
    delta_is("{\"fds\":9}", "{\"fds\":10}", "fds", "==", "1", 1,
             "a leaked fd is +1");
    delta_is("{\"fds\":9}", "{\"fds\":10}", "fds", "==", "0", 0,
             "a leaked fd is not 0");
    delta_is("{\"fds\":10}", "{\"fds\":9}", "fds", "==", "-1", 1,
             "a negative delta keeps its sign");
    delta_is("{\"n\":5}", "{\"n\":9}", "n", "<=", "4", 1, "<= on a delta");
    delta_is("{\"n\":5}", "{\"n\":9}", "n", "<", "4", 0, "< on a delta");
    delta_is("{\"n\":5}", "{\"n\":9}", "n", ">", "3", 1, "> on a delta");
    delta_is("{\"n\":5}", "{\"n\":9}", "n", "!=", "0", 1, "!= on a delta");
    delta_is("{\"a\":{\"b\":1}}", "{\"a\":{\"b\":4}}", "a.b", "==", "3", 1,
             "a nested delta");

    /*
     * THE case. -1 means the probe could not read /proc/self/fd at all. Both
     * snapshots carry it, the subtraction cancels to 0, and `delta fds == 0`
     * would pass in every consuming module while measuring nothing. An
     * assertion that cannot fail is worse than one that is missing, because
     * the green is believed.
     */
    delta_is("{\"fds\":-1}", "{\"fds\":-1}", "fds", "==", "0", 0,
             "an unavailable fd count fails rather than cancelling to zero");
    delta_is("{\"fds\":-1}", "{\"fds\":9}", "fds", "==", "10", 0,
             "an unavailable fd count in the before snapshot fails");
    delta_is("{\"fds\":9}", "{\"fds\":-1}", "fds", "==", "-10", 0,
             "an unavailable fd count in the after snapshot fails");

    /* -1 is only special for fds; a module counter may legitimately hold it. */
    delta_is("{\"zone\":{\"n\":-1}}", "{\"zone\":{\"n\":-1}}", "zone.n", "==",
             "0", 1, "-1 is not special outside fds");

    /* A path that changes shape between snapshots is a broken probe, not a
     * delta of zero. */
    delta_is("{\"n\":1}", "{\"m\":1}", "n", "==", "0", 0,
             "a path absent from the after snapshot fails");
    delta_is("{\"m\":1}", "{\"n\":1}", "n", "==", "0", 0,
             "a path absent from the before snapshot fails");
    delta_is("{\"n\":1}", "{\"n\":\"1\"}", "n", "==", "0", 0,
             "a path that turns into a string fails");
    delta_is("{\"n\":\"1\"}", "{\"n\":1}", "n", "==", "0", 0,
             "a path that starts as a string fails");
    delta_is("{\"n\":true}", "{\"n\":true}", "n", "==", "0", 0,
             "a boolean has no delta");
    delta_is("{\"n\":1}", "{\"n\":2}", "n", "==", "one", 0,
             "a non-numeric delta literal fails");
    delta_is("{\"n\":1}", "{\"n\":2}", "n", "==", "1x", 0,
             "a delta literal with trailing junk fails");

    /*
     * Worker survival. This oracle runs on every case rather than on request,
     * so a wrong verdict here is not a rule that misfires but a crash the whole
     * suite stops reporting -- which is the failure the check exists to catch.
     */
    pid_is("{\"pid\":4321}", "{\"pid\":4321}", 1,
           "an unchanged pid passes");
    pid_is("{\"pid\":4321}", "{\"pid\":4322}", 0,
           "a changed pid fails: the worker was respawned");

    /* A missing or non-numeric pid must fail rather than pass silently: absence
     * of evidence would otherwise read as evidence of survival. */
    pid_is("{\"pid\":4321}", "{}", 0,
           "a pid missing from the after snapshot fails");
    pid_is("{}", "{\"pid\":4321}", 0,
           "a pid missing from the before snapshot fails");
    pid_is("{\"pid\":\"4321\"}", "{\"pid\":\"4321\"}", 0,
           "a string pid fails even when both sides agree");
    pid_is("{\"pid\":null}", "{\"pid\":null}", 0,
           "a null pid fails even when both sides agree");

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        failures++;
    }

    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
