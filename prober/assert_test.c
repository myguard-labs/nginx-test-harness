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
#define PLANNED  106

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


/*
 * Drive eval_expect() over a synthetic response. Ownership mirrors the real
 * flow: the expectation's text is heap-owned as rules.c would leave it, and
 * for EXPECT_STATUS_LIKE the regex is compiled here the way the parser does,
 * because eval_expect() receives it already compiled.
 */
static void
expect_is(expect_kind kind, long number, const char *text, int status,
          const char *headers, const char *body, int want, const char *name)
{
    char           why[512] = "";
    expectation    e;
    http_response  resp;
    int            got;

    memset(&e, 0, sizeof(e));
    memset(&resp, 0, sizeof(resp));

    e.kind = kind;
    e.number = number;
    e.text = (text != NULL) ? xstrdup(text) : NULL;

    if (kind == EXPECT_STATUS_LIKE
        && regcomp(&e.re, text, REG_EXTENDED | REG_NOSUB) != 0)
    {
        printf("# %s: fixture regex \"%s\" does not compile\n", name, text);
        ok(0, name);
        free(e.text);
        return;
    }

    resp.status = status;
    resp.headers = (headers != NULL) ? xstrdup(headers) : NULL;
    resp.body = (body != NULL) ? xstrdup(body) : NULL;
    resp.body_len = (body != NULL) ? strlen(body) : 0;

    got = eval_expect(&e, &resp, why, sizeof(why));

    check(got, want, why, name);

    if (kind == EXPECT_STATUS_LIKE) {
        regfree(&e.re);
    }

    free(e.text);
    free(resp.headers);
    free(resp.body);
}


/* Compile pattern, ask log_lines_match() about buf, compare the verdict. */
static void
log_match_is(const char *buf, const char *pattern, int want, const char *name)
{
    regex_t  re;
    int      got;

    if (regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB) != 0) {
        printf("# %s: fixture regex \"%s\" does not compile\n", name, pattern);
        ok(0, name);
        return;
    }

    got = log_lines_match(buf, strlen(buf), &re);
    regfree(&re);

    if (got != want) {
        printf("# %s: verdict %d, want %d\n", name, got, want);
    }

    ok(got == want, name);
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

    /* ---- eval_expect: the positive forms, now reachable off-server ----- */

    expect_is(EXPECT_STATUS, 200, NULL, 200, NULL, NULL, 1,
              "expect status= on the matching code");
    expect_is(EXPECT_STATUS, 200, NULL, 404, NULL, NULL, 0,
              "expect status= on the wrong code");
    expect_is(EXPECT_BODY_CONTAINS, 0, "hello", 200, NULL, "say hello now",
              1, "body~ finds its needle");
    expect_is(EXPECT_BODY_CONTAINS, 0, "hello", 200, NULL, "goodbye",
              0, "body~ misses and fails");
    expect_is(EXPECT_BODY_CONTAINS, 0, "hello", 200, NULL, NULL,
              0, "body~ against a response with no body fails");
    expect_is(EXPECT_HEADER_CONTAINS, 0, "X-Test: on", 200,
              "Content-Type: text/html\r\nX-Test: on", NULL, 1,
              "header~ finds its header line");
    expect_is(EXPECT_HEADER_CONTAINS, 0, "X-Test: on", 200,
              "Content-Type: text/html", NULL, 0,
              "header~ misses and fails");

    /* ---- eval_expect: expect_not, the inverted pair -------------------- */

    expect_is(EXPECT_NOT_BODY_CONTAINS, 0, "oops", 200, NULL, "all fine",
              1, "expect_not body~ passes when the needle is absent");
    expect_is(EXPECT_NOT_BODY_CONTAINS, 0, "oops", 200, NULL, "well oops",
              0, "expect_not body~ fails when the needle appears");
    expect_is(EXPECT_NOT_BODY_CONTAINS, 0, "oops", 200, NULL, NULL,
              1, "expect_not body~ passes on a response with no body");
    expect_is(EXPECT_NOT_HEADER_CONTAINS, 0, "X-Debug", 200,
              "Content-Type: text/html", NULL, 1,
              "expect_not header~ passes when the header is absent");
    expect_is(EXPECT_NOT_HEADER_CONTAINS, 0, "X-Debug", 200,
              "X-Debug: 1\r\nContent-Type: text/html", NULL, 0,
              "expect_not header~ fails when the header is present");

    /* ---- eval_expect: error_code_like ---------------------------------- */

    expect_is(EXPECT_STATUS_LIKE, 0, "^2[0-9]{2}$", 204, NULL, NULL, 1,
              "error_code_like matches its status class");
    expect_is(EXPECT_STATUS_LIKE, 0, "^2[0-9]{2}$", 404, NULL, NULL, 0,
              "error_code_like fails outside its class");
    expect_is(EXPECT_STATUS_LIKE, 0, "^(403|429)$", 429, NULL, NULL, 1,
              "an alternation matches either code");
    expect_is(EXPECT_STATUS_LIKE, 0, "^-1$", -1, NULL, NULL, 1,
              "an unparseable status is matchable as the literal -1");
    expect_is(EXPECT_STATUS_LIKE, 0, "^200$", -1, NULL, NULL, 0,
              "an unparseable status does not match a real code");

    /* ---- log_lines_match ------------------------------------------------ */

    log_match_is("first line\nbad thing here\nlast line\n", "bad thing",
                 1, "a middle log line matches");
    log_match_is("first line\nsecond line\n", "bad thing",
                 0, "no line matching returns 0");
    log_match_is("", "anything", 0, "an empty slice matches nothing");
    log_match_is("tail without newline", "without",
                 1, "a trailing unterminated line is still matched");
    log_match_is("head\ntail", "^tail$",
                 1, "anchors apply per line, not per buffer");

    /* Matching is per line, like grep: a pattern must not be satisfiable by
     * text that spans a newline, which an unsplit regexec over the whole
     * buffer would happily allow ('.' matches \n in POSIX EREs). */
    log_match_is("ab\ncd", "b.c", 0,
                 "a pattern cannot match across a line boundary");

    /* ---- eval_close_within ---------------------------------------------- */

    /*
     * The verdict layer, over fixed values. http_test.c proves the transport
     * produces these correctly from a real socket; what matters here is that
     * each outcome is judged the right way -- and in particular that the three
     * failing ones all FAIL, since an evaluator that returns pass where it
     * should return fail makes every rule depending on it report green.
     */
    {
        http_response  resp;
        char           why[256];

        memset(&resp, 0, sizeof(resp));

        resp.close_reason = HTTP_CLOSE_FIN;
        resp.close_ms = 40;
        ok(eval_close_within(&resp, 250, why, sizeof(why)) == 1,
           "a close inside the deadline passes");

        /* The boundary is inclusive: closing exactly AT the deadline met it. */
        resp.close_ms = 250;
        ok(eval_close_within(&resp, 250, why, sizeof(why)) == 1,
           "a close exactly on the deadline passes");

        resp.close_ms = 251;
        ok(eval_close_within(&resp, 250, why, sizeof(why)) == 0,
           "a close one millisecond late fails");

        /* The reason text must carry the measured time: "too slow" and "never
         * closed" need different fixes, and the number is what tells them
         * apart when a run is read after the fact. */
        resp.close_ms = 4000;
        (void) eval_close_within(&resp, 250, why, sizeof(why));
        ok(strstr(why, "4000") != NULL && strstr(why, "250") != NULL,
           "a late close reports both the measured time and the deadline");

        /* A reset is still a close -- the connection is gone, which is what was
         * asserted -- but a LATE one must say so distinctly, since a server
         * that resets is not merely slow. */
        resp.close_reason = HTTP_CLOSE_RESET;
        resp.close_ms = 40;
        ok(eval_close_within(&resp, 250, why, sizeof(why)) == 1,
           "a prompt reset counts as a close");

        resp.close_ms = 4000;
        (void) eval_close_within(&resp, 250, why, sizeof(why));
        ok(strstr(why, "reset") != NULL,
           "a late reset is named as a reset, not just a slow close");

        resp.close_reason = HTTP_CLOSE_TIMEOUT;
        resp.close_ms = 300;
        ok(eval_close_within(&resp, 250, why, sizeof(why)) == 0,
           "a connection still open at the deadline fails");

        /*
         * No close observed at all. The parser rejects the directive
         * combinations that reach here, so this is a harness defect rather
         * than a rule-file one -- and it must fail rather than pass, because
         * "nothing was measured" silently treated as success is exactly the
         * vacuous green this file exists to prevent.
         */
        resp.close_reason = HTTP_CLOSE_NONE;
        resp.close_ms = 0;
        ok(eval_close_within(&resp, 250, why, sizeof(why)) == 0,
           "an unobserved close fails rather than passing vacuously");

        /* A zero deadline is unsatisfiable by anything that took real time,
         * which is what makes it coherent to spell. */
        resp.close_reason = HTTP_CLOSE_FIN;
        resp.close_ms = 1;
        ok(eval_close_within(&resp, 0, why, sizeof(why)) == 0,
           "a zero deadline rejects a close that took any time at all");

        /* The idle-wait reasons reach a close deadline only through a harness
         * defect (the parser rejects the combination), but the evaluator must
         * still refuse them rather than fall through to a pass. */
        resp.close_reason = HTTP_CLOSE_IDLE;
        resp.close_ms = 40;
        ok(eval_close_within(&resp, 250, why, sizeof(why)) == 0,
           "an idle-wait outcome fails a close deadline rather than passing");

        resp.close_reason = HTTP_CLOSE_DATA;
        ok(eval_close_within(&resp, 250, why, sizeof(why)) == 0,
           "a data outcome fails a close deadline rather than passing");
    }

    /* ---- eval_readable --------------------------------------------------- */

    /*
     * The mirror of the block above, with the polarity reversed: here the
     * server ACTING is the failure and silence is the pass. The same rule
     * governs it -- every non-pass outcome must actually fail, since this is
     * the assertion whose passing branch is a non-event and therefore the
     * easiest one to satisfy vacuously.
     */
    {
        http_response  resp;
        char           why[256];

        memset(&resp, 0, sizeof(resp));

        resp.close_reason = HTTP_CLOSE_IDLE;
        resp.close_ms = 200;
        ok(eval_readable(&resp, 200, why, sizeof(why)) == 1,
           "a connection left open and silent passes the idle wait");

        /* Data is a failure, and must be named as an answer rather than as a
         * close -- the distinction the directive exists to draw. */
        resp.close_reason = HTTP_CLOSE_DATA;
        resp.close_ms = 40;
        ok(eval_readable(&resp, 200, why, sizeof(why)) == 0,
           "a server that sent data fails the idle wait");

        (void) eval_readable(&resp, 200, why, sizeof(why));
        ok(strstr(why, "data") != NULL && strstr(why, "40") != NULL
           && strstr(why, "200") != NULL,
           "a data failure reports the action, the time and the wait");

        /* A close is a failure too, named by its manner: a server that resets
         * an idle connection is doing something other than closing it. */
        resp.close_reason = HTTP_CLOSE_FIN;
        ok(eval_readable(&resp, 200, why, sizeof(why)) == 0,
           "a server that closed fails the idle wait");

        (void) eval_readable(&resp, 200, why, sizeof(why));
        ok(strstr(why, "closed") != NULL && strstr(why, "data") == NULL,
           "a close failure is named as a close, not as data");

        resp.close_reason = HTTP_CLOSE_RESET;
        (void) eval_readable(&resp, 200, why, sizeof(why));
        ok(eval_readable(&resp, 200, why, sizeof(why)) == 0
           && strstr(why, "reset") != NULL,
           "a reset during the wait is named as a reset");

        /*
         * No idle wait ran. Like eval_close_within's HTTP_CLOSE_NONE arm this
         * is unreachable from a valid rule file, and like it this must fail:
         * an unhandled reason silently becoming a pass is precisely how an
         * assertion that tests nothing reports green forever.
         */
        resp.close_reason = HTTP_CLOSE_NONE;
        resp.close_ms = 0;
        ok(eval_readable(&resp, 200, why, sizeof(why)) == 0,
           "an unperformed idle wait fails rather than passing vacuously");

        resp.close_reason = HTTP_CLOSE_TIMEOUT;
        ok(eval_readable(&resp, 200, why, sizeof(why)) == 0,
           "a read-loop timeout fails an idle wait rather than passing");
    }

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        failures++;
    }

    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
