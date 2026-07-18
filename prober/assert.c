/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * assert.c -- see assert.h.
 */

/* memmem() is GNU/POSIX-2024, not C11, and the build asks for -std=c11
 * strictly -- same dance as util.c. */
#define _GNU_SOURCE

#include "assert.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int
compare_number(double have, const char *op, double want)
{
    if (strcmp(op, "==") == 0) return have == want;
    if (strcmp(op, "!=") == 0) return have != want;
    if (strcmp(op, "<")  == 0) return have <  want;
    if (strcmp(op, "<=") == 0) return have <= want;
    if (strcmp(op, ">")  == 0) return have >  want;
    if (strcmp(op, ">=") == 0) return have >= want;

    /* The rule parser accepts only the operators above (plus "~", which never
     * reaches a numeric comparison), so arriving here means the two lists have
     * drifted apart -- a harness bug, not a user one. */
    die("unknown numeric operator \"%s\"", op);
}


const char *
unquote(const char *lit, char *scratch, size_t scratchlen)
{
    size_t len = strlen(lit);

    if (len >= 2 && lit[0] == '"' && lit[len - 1] == '"') {
        if (len - 1 >= scratchlen) {
            return NULL;
        }

        memcpy(scratch, lit + 1, len - 2);
        scratch[len - 2] = '\0';

        return scratch;
    }

    return lit;
}


/*
 * Parse a rule literal as a number, rejecting anything with trailing text.
 *
 * strtod() stops at the first character it cannot use and reports success for
 * the prefix, so "1x" would otherwise compare as 1 and a mistyped expectation
 * would quietly assert something nobody wrote.
 */
static int
literal_number(const char *want, double *out)
{
    char *stop;

    if (*want == '\0') {
        return 0;
    }

    *out = strtod(want, &stop);

    return (stop != want && *stop == '\0');
}


int
eval_expect(const expectation *e, const http_response *resp, char *why,
            size_t whylen)
{
    switch (e->kind) {

    case EXPECT_STATUS:
        if (resp->status != (int) e->number) {
            snprintf(why, whylen, "status: have %d, want %ld",
                     resp->status, e->number);
            return 0;
        }
        return 1;

    case EXPECT_BODY_CONTAINS:
        if (resp->body == NULL
            || memmem(resp->body, resp->body_len,
                      e->text, strlen(e->text)) == NULL)
        {
            snprintf(why, whylen, "body does not contain \"%.128s\"", e->text);
            return 0;
        }
        return 1;

    case EXPECT_HEADER_CONTAINS:
        if (!http_has_header(resp, e->text)) {
            snprintf(why, whylen, "no header matching \"%.128s\"", e->text);
            return 0;
        }
        return 1;

    case EXPECT_NOT_BODY_CONTAINS:
        /* An absent body trivially does not contain the needle, so it PASSES
         * here -- the negative matcher asserts absence, and a response with
         * no body is the strongest form of absence there is. A rule that also
         * needs the body to exist says so with a positive expect. */
        if (resp->body != NULL
            && memmem(resp->body, resp->body_len,
                      e->text, strlen(e->text)) != NULL)
        {
            snprintf(why, whylen, "body contains \"%.128s\", expected not to",
                     e->text);
            return 0;
        }
        return 1;

    case EXPECT_NOT_HEADER_CONTAINS:
        if (http_has_header(resp, e->text)) {
            snprintf(why, whylen, "header matches \"%.128s\", expected not to",
                     e->text);
            return 0;
        }
        return 1;

    case EXPECT_STATUS_LIKE: {
        char  code[16];
        int   n;

        /* -1 (unparseable status line) is rendered literally, so a rule can
         * assert on garbage on purpose: `error_code_like ^-1$`. */
        n = snprintf(code, sizeof(code), "%d", resp->status);

        if (n < 0 || (size_t) n >= sizeof(code)
            || regexec(&e->re, code, 0, NULL, 0) != 0)
        {
            snprintf(why, whylen, "status %d does not match /%.128s/",
                     resp->status, e->text);
            return 0;
        }
        return 1;
    }
    }

    /* Unreachable with a well-formed expectation; the parser assigns every
     * kind in the enum. Same drift guard as compare_number()'s. */
    die("unknown expect kind %d", (int) e->kind);
}


int
log_lines_match(const char *buf, size_t len, const regex_t *re)
{
    char   *copy, *line, *save = NULL;
    int     matched = 0;

    if (len == 0) {
        return 0;
    }

    /*
     * One heap copy with newlines turned into terminators, rather than a
     * fixed per-line stack buffer: nginx error-log lines routinely exceed any
     * comfortable stack bound (a request line is echoed into them verbatim),
     * and a matcher that silently truncates is a matcher that misses exactly
     * the oversized line worth catching.
     */
    copy = malloc(len + 1);
    if (copy == NULL) {
        die("out of memory");
    }

    memcpy(copy, buf, len);
    copy[len] = '\0';

    for (line = strtok_r(copy, "\n", &save);
         line != NULL && !matched;
         line = strtok_r(NULL, "\n", &save))
    {
        matched = (regexec(re, line, 0, NULL, 0) == 0);
    }

    free(copy);

    return matched;
}


int
eval_probe(const json_value *doc, const probe_assert *pa, char *why,
           size_t whylen)
{
    char              scratch[512];
    const char       *want;
    const json_value *v;

    v = json_get(doc, pa->path);

    if (v == NULL) {
        snprintf(why, whylen, "probe path \"%.128s\" not present in document",
                 pa->path);
        return 0;
    }

    want = unquote(pa->literal, scratch, sizeof(scratch));

    if (want == NULL) {
        snprintf(why, whylen,
                 "probe %.128s: literal is longer than %zu bytes",
                 pa->path, sizeof(scratch) - 1);
        return 0;
    }

    switch (v->type) {

    case JSON_NUMBER: {
        double wanted;

        if (!literal_number(want, &wanted)) {
            snprintf(why, whylen,
                     "%.128s is a number but the rule compares it to \"%.128s\"",
                     pa->path, want);
            return 0;
        }

        if (!compare_number(v->number, pa->op, wanted)) {
            snprintf(why, whylen, "%.128s: have %g, want %.16s %.128s",
                     pa->path, v->number, pa->op, want);
            return 0;
        }

        return 1;
    }

    case JSON_STRING:
        if (strcmp(pa->op, "==") == 0) {
            if (strcmp(v->string, want) != 0) {
                snprintf(why, whylen, "%.128s: have \"%.128s\", want \"%.128s\"",
                         pa->path, v->string, want);
                return 0;
            }
            return 1;
        }

        if (strcmp(pa->op, "!=") == 0) {
            if (strcmp(v->string, want) == 0) {
                snprintf(why, whylen, "%.128s: have \"%.128s\", want != \"%.128s\"",
                         pa->path, v->string, want);
                return 0;
            }
            return 1;
        }

        if (strcmp(pa->op, "~") == 0) {
            if (strstr(v->string, want) == NULL) {
                snprintf(why, whylen, "%.128s: \"%.128s\" does not contain \"%.128s\"",
                         pa->path, v->string, want);
                return 0;
            }
            return 1;
        }

        snprintf(why, whylen, "operator \"%.32s\" is not valid on a string",
                 pa->op);
        return 0;

    case JSON_BOOL: {
        int wanted = (strcmp(want, "true") == 0);

        if (strcmp(want, "true") != 0 && strcmp(want, "false") != 0) {
            snprintf(why, whylen,
                     "%.128s is a boolean but the rule compares it to \"%.128s\"",
                     pa->path, want);
            return 0;
        }

        if (strcmp(pa->op, "==") == 0) {
            if (v->boolean != wanted) {
                snprintf(why, whylen, "%.128s: have %s, want %.128s", pa->path,
                         v->boolean ? "true" : "false", want);
                return 0;
            }
            return 1;
        }

        if (strcmp(pa->op, "!=") == 0) {
            if (v->boolean == wanted) {
                snprintf(why, whylen, "%.128s: have %s, want != %.128s",
                         pa->path, v->boolean ? "true" : "false", want);
                return 0;
            }
            return 1;
        }

        snprintf(why, whylen, "operator \"%.32s\" is not valid on a boolean",
                 pa->op);
        return 0;
    }

    default:
        snprintf(why, whylen, "%.128s is of type %s, which cannot be compared",
                 pa->path, json_type_name(v->type));
        return 0;
    }
}


int
eval_delta(const json_value *before, const json_value *after,
           const probe_assert *pa, char *why, size_t whylen)
{
    char              scratch[512];
    double            wanted, change;
    const char       *want;
    const json_value *b, *a;

    b = json_get(before, pa->path);
    a = json_get(after, pa->path);

    if (b == NULL || a == NULL) {
        snprintf(why, whylen, "delta path \"%.128s\" is not present in the %s "
                 "snapshot", pa->path, (b == NULL) ? "before" : "after");
        return 0;
    }

    if (b->type != JSON_NUMBER || a->type != JSON_NUMBER) {
        snprintf(why, whylen, "delta path \"%.128s\" is %s/%s, not a number",
                 pa->path, json_type_name(b->type), json_type_name(a->type));
        return 0;
    }

    /*
     * "fds" is -1 when the probe could not read /proc/self/fd at all. Both
     * snapshots then carry -1, and the subtraction below cancels them into a
     * delta of 0 -- so every `delta fds == 0` rule would PASS while measuring
     * nothing. An assertion that cannot fail is worse than a missing one.
     */
    if (strcmp(pa->path, "fds") == 0
        && (b->number == -1 || a->number == -1))
    {
        snprintf(why, whylen,
                 "delta path \"fds\" is unavailable (-1) in the %s snapshot",
                 (b->number == -1) ? "before" : "after");
        return 0;
    }

    want = unquote(pa->literal, scratch, sizeof(scratch));

    if (want == NULL) {
        snprintf(why, whylen, "delta %.128s: literal is longer than %zu bytes",
                 pa->path, sizeof(scratch) - 1);
        return 0;
    }

    if (!literal_number(want, &wanted)) {
        snprintf(why, whylen, "delta %.128s: \"%.128s\" is not a number",
                 pa->path, want);
        return 0;
    }

    change = a->number - b->number;

    if (!compare_number(change, pa->op, wanted)) {
        snprintf(why, whylen,
                 "delta %.128s: %g -> %g is %+g, want %.16s %.128s",
                 pa->path, b->number, a->number, change, pa->op, want);
        return 0;
    }

    return 1;
}


int
eval_pid_stable(const json_value *before, const json_value *after,
                char *why, size_t whylen)
{
    const json_value *b, *a;

    b = json_get(before, "pid");
    a = json_get(after, "pid");

    if (b == NULL || a == NULL) {
        snprintf(why, whylen, "\"pid\" is not present in the %s snapshot, so "
                 "worker survival cannot be established",
                 (b == NULL) ? "before" : "after");
        return 0;
    }

    if (b->type != JSON_NUMBER || a->type != JSON_NUMBER) {
        snprintf(why, whylen, "\"pid\" is %s/%s, not a number",
                 json_type_name(b->type), json_type_name(a->type));
        return 0;
    }

    /*
     * Compared as doubles because that is how the JSON reader stores every
     * number. A pid is far below 2^53, so the representation is exact and
     * equality here means equality of the integers the probe printed.
     */
    if (b->number != a->number) {
        snprintf(why, whylen, "worker pid changed %g -> %g: the worker died "
                 "and was respawned during this case", b->number, a->number);
        return 0;
    }

    return 1;
}
