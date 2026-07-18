/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * json_test.c -- TAP self-test for the prober's JSON reader.
 *
 * The reader is the harness ORACLE: every `probe` and `delta` assertion is
 * evaluated against the document it produces. A parser that quietly accepts a
 * malformed document, or that reads a number wrong, turns every rule that
 * depends on it into a test that cannot fail -- which is worse than having no
 * rule at all, because the run still reports green.
 *
 * So the accept cases pin the shapes the probe renderer actually emits, and the
 * reject cases pin the shapes that would mean the renderer is broken (raw
 * control bytes in a string, leading-zero or leading-plus numbers, truncated
 * documents). Run by t/prober/run.sh before any server is booted.
 */

#define _GNU_SOURCE

#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bumped by hand rather than computed, so that a test accidentally deleted or
 * short-circuited shows up as a plan mismatch instead of a smaller green run. */
#define PLANNED  50

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


static void
accepts(const char *text, const char *name)
{
    const char *err = NULL;
    json_value *v = json_parse(text, &err);

    if (v == NULL) {
        printf("# %s: rejected with \"%s\"\n", name, err ? err : "?");
    }

    ok(v != NULL, name);
    json_free(v);
}


static void
rejects(const char *text, const char *name)
{
    const char *err = NULL;
    json_value *v = json_parse(text, &err);

    if (v != NULL) {
        printf("# %s: accepted, but must not be\n", name);
    }

    ok(v == NULL, name);
    json_free(v);
}


/*
 * Reject, AND for the stated reason. Several of the rejections below are the
 * only thing standing between a malformed document and a confident wrong
 * verdict, so it matters that the parser refuses them deliberately rather than
 * tripping over some earlier check by luck -- a rejection that moves to a
 * different cause is a rejection that can quietly stop happening.
 */
static void
rejects_because(const char *text, const char *want_err, const char *name)
{
    const char *err = NULL;
    json_value *v = json_parse(text, &err);
    int         good;

    good = (v == NULL && err != NULL && strcmp(err, want_err) == 0);

    if (!good) {
        printf("# %s: got %s (\"%s\"), want rejection \"%s\"\n", name,
               v == NULL ? "rejection" : "acceptance", err ? err : "-",
               want_err);
    }

    ok(good, name);
    json_free(v);
}


static void
number_is(const char *text, const char *path, double want, const char *name)
{
    const char       *err = NULL;
    const json_value *field;
    json_value       *doc = json_parse(text, &err);
    int               good;

    if (doc == NULL) {
        printf("# %s: parse failed: %s\n", name, err ? err : "?");
        ok(0, name);
        return;
    }

    field = json_get(doc, path);
    good = (field != NULL && field->type == JSON_NUMBER && field->number == want);

    if (!good) {
        printf("# %s: %s is %s\n", name, path,
               field == NULL ? "absent" : json_type_name(field->type));
    }

    ok(good, name);
    json_free(doc);
}


int
main(void)
{
    /* The document the probe renderer actually emits, in the shape the rule
     * files assert against. If this ever stops parsing, every rule breaks at
     * once, so it is the first thing checked. */
    static const char probe_doc[] =
        "{\"flavor\":\"nginx\",\"flavor_version\":\"1.31.3\",\"pid\":1234,"
        "\"page_size\":4096,\"connections\":{\"total\":512,\"free\":511},"
        "\"zone\":{\"present\":true,\"name\":\"demo\",\"size\":1048576,"
        "\"slab_pages_free\":248,\"nodes\":2,\"banned\":1,"
        "\"fault\":{\"slab_nth\":-1,\"slab_seen\":0}}}";

    printf("1..%d\n", PLANNED);

    accepts(probe_doc, "the probe document parses");
    number_is(probe_doc, "zone.nodes", 2, "a nested number reads back");
    number_is(probe_doc, "zone.fault.slab_nth", -1,
              "a negative number keeps its sign");
    number_is(probe_doc, "connections.free", 511, "a two-level path resolves");

    {
        json_value *doc = json_parse(probe_doc, NULL);

        ok(doc != NULL && json_get(doc, "zone.absent") == NULL,
           "an absent path is NULL, not a zero");
        json_free(doc);
    }

    /* Numbers: the JSON grammar, not what strtod() happens to swallow. */
    accepts("{\"n\":0}", "zero");
    accepts("{\"n\":-0}", "negative zero");
    accepts("{\"n\":1234567890}", "a plain integer");
    accepts("{\"n\":1.5}", "a fraction");
    accepts("{\"n\":1e3}", "an exponent");
    rejects("{\"n\":+1}", "a leading plus is not JSON");
    rejects("{\"n\":.5}", "a bare fraction is not JSON");
    rejects("{\"n\":01}", "a leading zero is not JSON");
    rejects("{\"n\":1.}", "a trailing decimal point is not JSON");
    rejects("{\"n\":1e}", "an empty exponent is not JSON");
    rejects("{\"n\":0x10}", "hex is not JSON");
    rejects("{\"n\":"
            "111111111111111111111111111111111111111111111111111111111111"
            "111111111111111111111111}",
            "an over-long number is an error, not a truncation");

    /* Strings. */
    accepts("{\"s\":\"a\\nb\"}", "an escaped newline");
    rejects("{\"s\":\"a\nb\"}", "a raw newline in a string");
    rejects("{\"s\":\"a\tb\"}", "a raw tab in a string");
    rejects("{\"s\":\"unterminated}", "an unterminated string");

    /* Document framing. */
    rejects("{\"a\":1", "a truncated object");
    rejects("{\"a\":1}}", "trailing garbage after the document");
    rejects("", "an empty document");

    /*
     * Duplicate keys.
     *
     * json_get() returns the first match, so a second value for the same key
     * can never be asserted on -- and the way one appears is a module's
     * zone_render hook emitting a member the generic probe already emitted.
     * That is a defect in the code under test, and it has to surface as a
     * broken probe rather than as one value silently shadowing another.
     */
    rejects_because("{\"a\":1,\"a\":2}", "duplicate key in object",
                    "a duplicate key is rejected, not shadowed");
    rejects_because("{\"zone\":{\"n\":1,\"n\":2}}", "duplicate key in object",
                    "a duplicate key nested in an object is rejected");
    accepts("{\"a\":{\"n\":1},\"b\":{\"n\":2}}",
            "the same key in two different objects is fine");

    /*
     * Numbers that do not survive as a finite double. Infinity compares as a
     * number under every operator, so `probe x < 100` against an infinite
     * value would report a clean, confident, wrong verdict.
     */
    rejects_because("{\"n\":1e999}", "number is out of range for a double",
                    "an overflowing exponent is rejected, not read as infinity");
    rejects_because("{\"n\":-1e999}", "number is out of range for a double",
                    "a negative overflowing exponent is rejected too");
    accepts("{\"n\":1e308}", "an exponent that still fits a double");

    /* Nesting. The parser recurses, and the document comes from a worker that
     * may be in the middle of crashing. */
    {
        char deep[4096];
        char shallow[256];
        int  i;

        for (i = 0; i < JSON_MAX_DEPTH + 5; i++) {
            deep[i] = '[';
        }
        deep[JSON_MAX_DEPTH + 5] = '\0';

        rejects_because(deep, "nesting too deep",
                        "nesting past the depth cap is refused");

        /* One below the cap must still parse, or the cap is off by one and
         * quietly rejects documents the probe can legitimately emit. */
        for (i = 0; i < JSON_MAX_DEPTH - 1; i++) {
            shallow[i] = '[';
        }
        shallow[JSON_MAX_DEPTH - 1] = ']';
        for (i = 0; i < JSON_MAX_DEPTH - 2; i++) {
            shallow[JSON_MAX_DEPTH + i] = ']';
        }
        shallow[2 * JSON_MAX_DEPTH - 2] = '\0';

        accepts(shallow, "nesting just under the cap still parses");
    }

    /* Paths. */
    {
        json_value *doc = json_parse(probe_doc, NULL);

        ok(doc != NULL && json_get(doc, "") == NULL,
           "an empty path is not the whole document");
        ok(doc != NULL && json_get(doc, "zone.nodes.deeper") == NULL,
           "descending through a number yields NULL");
        ok(doc != NULL && json_get(doc, "zon") == NULL,
           "a key prefix does not match");
        ok(doc != NULL && json_get(doc, "zone.") == NULL,
           "a trailing dot does not resolve to the parent");
        ok(doc != NULL && json_get(doc, ".zone") == NULL,
           "a leading dot does not resolve");
        ok(doc != NULL && json_get(doc, "zone..nodes") == NULL,
           "a doubled dot does not resolve");

        json_free(doc);
    }

    /* Object and array framing that the probe renderer would only produce if
     * it were emitting a member it had not finished building. */
    rejects("{\"a\":}", "an object member with no value");
    rejects("{\"a\" 1}", "an object member with no colon");
    rejects("{,}", "a bare comma in an object");
    rejects("{\"a\":1,}", "a trailing comma in an object");
    rejects("[1,]", "a trailing comma in an array");
    rejects("[1,,2]", "a doubled comma in an array");
    rejects("{\"a\":1,\"b\"}", "a second member with no value");
    rejects("[", "an unterminated array");
    accepts("{}", "an empty object");
    accepts("[]", "an empty array");
    accepts("{\"a\":[]}", "an empty array as a member");

    /* Whitespace between every token, which ngx_slprintf never emits but a
     * hand-written fixture in a consumer's test might. */
    accepts("  {  \"a\" :  1 ,  \"b\" : [ 1 , 2 ]  }  ",
            "insignificant whitespace everywhere");

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        failures++;
    }

    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
