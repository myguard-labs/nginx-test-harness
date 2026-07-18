/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * rules.c -- see rules.h.
 */

#include "rules.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*
 * Decode the rule-file escapes into raw bytes appended to *buf.
 *
 * Note this is byte-exact and does no HTTP-level fixups whatsoever: no implied
 * CRLF at end of line, no Content-Length synthesis, no header ordering. The
 * point of the harness is that the request on the wire is the request in the
 * file.
 */
static void
append_escaped(unsigned char **buf, size_t *len, size_t *cap, const char *src)
{
    while (*src != '\0') {
        unsigned char c;

        if (*src == '\\' && src[1] != '\0') {
            src++;

            switch (*src) {
            case 'r':  c = '\r'; src++; break;
            case 'n':  c = '\n'; src++; break;
            case 't':  c = '\t'; src++; break;
            case '0':  c = '\0'; src++; break;
            case '\\': c = '\\'; src++; break;
            case '"':  c = '"';  src++; break;

            case 'x': {
                char  hex[3];
                int   i = 0;

                src++;

                while (i < 2 && isxdigit((unsigned char) src[i])) {
                    hex[i] = src[i];
                    i++;
                }

                if (i == 0) {
                    die("bad \\x escape in send line");
                }

                hex[i] = '\0';
                c = (unsigned char) strtol(hex, NULL, 16);
                src += i;
                break;
            }

            default:
                die("unknown escape \\%c in send line", *src);
            }

        } else {
            c = (unsigned char) *src++;
        }

        if (*len + 1 >= *cap) {
            unsigned char *bigger;

            *cap = (*cap == 0) ? 256 : *cap * 2;
            bigger = realloc(*buf, *cap);
            if (bigger == NULL) {
                die("out of memory");
            }
            *buf = bigger;
        }

        (*buf)[(*len)++] = c;
    }
}


void
case_free(test_case *tc)
{
    size_t i;

    free(tc->name);
    free(tc->fault);
    free(tc->source);
    free(tc->request);
    free(tc->xfail_reason);

    for (i = 0; i < tc->n_no_logs; i++) {
        free(tc->no_logs[i].pattern);
        regfree(&tc->no_logs[i].re);
    }

    for (i = 0; i < tc->n_grep_logs; i++) {
        free(tc->grep_logs[i].pattern);
        regfree(&tc->grep_logs[i].re);
    }

    for (i = 0; i < tc->n_expects; i++) {
        free(tc->expects[i].text);

        if (tc->expects[i].kind == EXPECT_STATUS_LIKE) {
            regfree(&tc->expects[i].re);
        }
    }

    for (i = 0; i < tc->n_probes; i++) {
        free(tc->probes[i].path);
        free(tc->probes[i].op);
        free(tc->probes[i].literal);
    }

    for (i = 0; i < tc->n_deltas; i++) {
        free(tc->deltas[i].path);
        free(tc->deltas[i].op);
        free(tc->deltas[i].literal);
    }

    memset(tc, 0, sizeof(*tc));
}


static void
parse_expect(test_case *tc, char *arg, const char *file, int lineno)
{
    expectation *e;

    if (tc->n_expects >= MAX_ASSERTS) {
        die("%s:%d: too many expect lines (max %d)",
            file, lineno, MAX_ASSERTS);
    }

    e = &tc->expects[tc->n_expects];

    if (strncmp(arg, "status=", 7) == 0) {
        char *stop;
        char *value = trim(arg + 7);

        e->kind = EXPECT_STATUS;
        e->text = NULL;
        e->number = strtol(value, &stop, 10);

        /* The whole token has to be the number. "status=200junk" silently
         * parsing as 200 would make a typo'd expectation assert something its
         * author did not write -- and, unlike a wrong number, it would keep
         * passing. `repeat` validates its count the same way and for the same
         * reason. */
        if (*value == '\0' || stop == value || *stop != '\0') {
            die("%s:%d: expect status=\"%s\" is not a number",
                file, lineno, value);
        }

    } else if (strncmp(arg, "body~", 5) == 0) {
        e->kind = EXPECT_BODY_CONTAINS;
        e->text = xstrdup(trim(arg + 5));

    } else if (strncmp(arg, "header~", 7) == 0) {
        e->kind = EXPECT_HEADER_CONTAINS;
        e->text = xstrdup(trim(arg + 7));

    } else {
        die("%s:%d: unknown expect form \"%s\" "
            "(want status=, body~, header~)", file, lineno, arg);
    }

    tc->n_expects++;
}


/*
 * `expect_not` is the negative counterpart of `expect`, restricted to the two
 * substring forms -- `body~`/`header~`. Status has no negative form here on
 * purpose: `error_code_like` already covers status-class assertions
 * (including "anything but 2xx" via the regex itself), so this directive's
 * shape stays exactly `expect`'s two substring forms, inverted, per the
 * brief.
 */
static void
parse_expect_not(test_case *tc, char *arg, const char *file, int lineno)
{
    expectation *e;

    if (tc->n_expects >= MAX_ASSERTS) {
        die("%s:%d: too many expect_not lines (max %d)",
            file, lineno, MAX_ASSERTS);
    }

    e = &tc->expects[tc->n_expects];

    if (strncmp(arg, "body~", 5) == 0) {
        e->kind = EXPECT_NOT_BODY_CONTAINS;
        e->text = xstrdup(trim(arg + 5));

        if (*e->text == '\0') {
            die("%s:%d: expect_not body~ needs a non-empty pattern",
                file, lineno);
        }

    } else if (strncmp(arg, "header~", 7) == 0) {
        e->kind = EXPECT_NOT_HEADER_CONTAINS;
        e->text = xstrdup(trim(arg + 7));

        if (*e->text == '\0') {
            die("%s:%d: expect_not header~ needs a non-empty pattern",
                file, lineno);
        }

    } else {
        die("%s:%d: unknown expect_not form \"%s\" (want body~, header~)",
            file, lineno, arg);
    }

    tc->n_expects++;
}


/*
 * `error_code_like <regex>` -- a POSIX extended regex matched against the
 * status code rendered as decimal text (e.g. "404", "204").
 *
 * Compiled here, at load time, for the same reason op_is_known() validates
 * operators up front: a malformed pattern dying mid-run truncates the TAP
 * stream, and a consumer reading a short plan cannot distinguish that from a
 * crash. Reject an empty pattern explicitly too -- regcomp() happily compiles
 * "" and it matches every status code, which is never what a rule author
 * meant to write.
 */
static void
parse_error_code_like(test_case *tc, char *arg, const char *file, int lineno)
{
    expectation *e;
    char        *pattern;
    int          rc;

    if (tc->n_expects >= MAX_ASSERTS) {
        die("%s:%d: too many error_code_like lines (max %d)",
            file, lineno, MAX_ASSERTS);
    }

    pattern = trim(arg);

    if (*pattern == '\0') {
        die("%s:%d: error_code_like needs a non-empty regex", file, lineno);
    }

    e = &tc->expects[tc->n_expects];
    e->kind = EXPECT_STATUS_LIKE;
    e->text = xstrdup(pattern);

    rc = regcomp(&e->re, pattern, REG_EXTENDED | REG_NOSUB);

    if (rc != 0) {
        char errbuf[256];

        regerror(rc, &e->re, errbuf, sizeof(errbuf));
        die("%s:%d: error_code_like \"%s\" is not a valid regex: %s",
            file, lineno, pattern, errbuf);
    }

    tc->n_expects++;
}


/*
 * `no_error_log <regex>` / `grep_error_log <regex>` -- shared parser, same
 * shape either way: one POSIX extended regex, compiled at load time for the
 * same die-before-the-first-request reason as error_code_like's. The empty
 * pattern is rejected explicitly here too, and for the sharper of the two
 * reasons: regcomp("") matches EVERY line, so an empty grep_error_log would
 * pass on any log at all and an empty no_error_log would fail on any line --
 * one vacuous, one unsatisfiable, both silently not what the author wrote.
 */
static void
parse_log_assert(log_assert *list, size_t *count, const char *directive,
                 char *arg, const char *file, int lineno)
{
    char        *pattern;
    int          rc;
    log_assert  *la;

    if (*count >= MAX_ASSERTS) {
        die("%s:%d: too many %s lines (max %d)", file, lineno, directive,
            MAX_ASSERTS);
    }

    pattern = trim(arg);

    if (*pattern == '\0') {
        die("%s:%d: %s needs a non-empty regex", file, lineno, directive);
    }

    la = &list[*count];
    la->pattern = xstrdup(pattern);

    rc = regcomp(&la->re, pattern, REG_EXTENDED | REG_NOSUB);

    if (rc != 0) {
        char errbuf[256];

        regerror(rc, &la->re, errbuf, sizeof(errbuf));
        die("%s:%d: %s \"%s\" is not a valid regex: %s",
            file, lineno, directive, pattern, errbuf);
    }

    (*count)++;
}


/*
 * Operators are validated here, at load time, rather than where they are
 * applied.
 *
 * The evaluator cannot do better than die() on an operator it does not know,
 * and dying mid-run truncates the TAP stream: the cases already printed stand,
 * the ones after never run, and a consumer sees a short plan rather than a
 * failure. Rejecting the rule file before the first request means the run
 * either happens completely or does not start.
 */
static int
op_is_known(const char *op)
{
    static const char *const ops[] = {
        "==", "!=", "<", "<=", ">", ">=", "~", NULL
    };
    size_t i;

    for (i = 0; ops[i] != NULL; i++) {
        if (strcmp(op, ops[i]) == 0) {
            return 1;
        }
    }

    return 0;
}


/*
 * Both `probe` and `delta` are <path> <op> <value>; they differ only in what
 * the left-hand side is measured against, so they share the parser and the
 * directive name is carried through purely for the error message.
 */
static void
parse_assert(probe_assert *list, size_t *count, const char *directive,
             char *arg, const char *file, int lineno)
{
    char         *path, *op, *lit;
    probe_assert *pa;

    if (*count >= MAX_ASSERTS) {
        die("%s:%d: too many %s lines (max %d)", file, lineno, directive,
            MAX_ASSERTS);
    }

    path = strtok(arg, " \t");
    op = strtok(NULL, " \t");
    lit = strtok(NULL, "");

    if (path == NULL || op == NULL || lit == NULL) {
        die("%s:%d: %s needs <path> <op> <value>", file, lineno, directive);
    }

    if (!op_is_known(op)) {
        die("%s:%d: %s: unknown operator \"%s\" "
            "(want ==, !=, <, <=, >, >=, ~)", file, lineno, directive, op);
    }

    /* `~` is a substring test, which only means anything on a string, and
     * `delta` subtracts, which only means anything on a number. Catching the
     * combination here rather than at evaluation time keeps the failure at the
     * line that caused it. */
    if (strcmp(directive, "delta") == 0 && strcmp(op, "~") == 0) {
        die("%s:%d: delta: \"~\" is a substring test and cannot apply to a "
            "numeric difference", file, lineno);
    }

    lit = trim(lit);

    if (*lit == '\0') {
        die("%s:%d: %s needs <path> <op> <value>", file, lineno, directive);
    }

    pa = &list[*count];
    pa->path = xstrdup(path);
    pa->op = xstrdup(op);
    pa->literal = xstrdup(lit);

    (*count)++;
}


size_t
load_rules(const char *file, test_case *cases, size_t max)
{
    FILE    *fp;
    char     line[4096];
    size_t   n = 0, cap = 0;
    int      lineno = 0;
    int      open_case = 0;

    fp = fopen(file, "r");
    if (fp == NULL) {
        die("cannot open rule file %s", file);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p, *directive, *arg;

        lineno++;

        p = line;

        /* Strip the newline only -- trailing spaces can be significant inside
         * a send line, so trimming happens per-directive, not here. */
        p[strcspn(p, "\n")] = '\0';

        {
            char *probe = p;

            while (*probe != '\0' && isspace((unsigned char) *probe)) {
                probe++;
            }

            if (*probe == '\0') {
                open_case = 0;                        /* blank line ends stanza */
                continue;
            }

            if (*probe == '#') {
                continue;
            }

            p = probe;
        }

        directive = p;

        while (*p != '\0' && !isspace((unsigned char) *p)) {
            p++;
        }

        if (*p != '\0') {
            *p++ = '\0';
        }

        while (*p != '\0' && (*p == ' ' || *p == '\t')) {
            p++;
        }

        arg = p;

        if (strcmp(directive, "name") == 0) {
            if (n >= max) {
                die("%s:%d: too many cases (max %zu)", file, lineno, max);
            }

            n++;
            cap = 0;
            open_case = 1;
            cases[n - 1].name = xstrdup(trim(arg));
            continue;
        }

        if (!open_case || n == 0) {
            die("%s:%d: \"%s\" before any name directive",
                file, lineno, directive);
        }

        if (strcmp(directive, "send") == 0) {
            append_escaped(&cases[n - 1].request, &cases[n - 1].request_len,
                           &cap, arg);

        } else if (strcmp(directive, "expect") == 0) {
            parse_expect(&cases[n - 1], trim(arg), file, lineno);

        } else if (strcmp(directive, "expect_not") == 0) {
            parse_expect_not(&cases[n - 1], trim(arg), file, lineno);

        } else if (strcmp(directive, "error_code_like") == 0) {
            parse_error_code_like(&cases[n - 1], arg, file, lineno);

        } else if (strcmp(directive, "no_error_log") == 0) {
            parse_log_assert(cases[n - 1].no_logs, &cases[n - 1].n_no_logs,
                             directive, arg, file, lineno);

        } else if (strcmp(directive, "grep_error_log") == 0) {
            parse_log_assert(cases[n - 1].grep_logs, &cases[n - 1].n_grep_logs,
                             directive, arg, file, lineno);

        } else if (strcmp(directive, "xfail") == 0) {
            if (cases[n - 1].xfail) {
                die("%s:%d: xfail already set for this case", file, lineno);
            }

            cases[n - 1].xfail = 1;

            /* A blank reason is allowed -- the annotation itself is the
             * signal; the text is diagnostic only. */
            {
                char *reason = trim(arg);

                cases[n - 1].xfail_reason =
                    (*reason != '\0') ? xstrdup(reason) : NULL;
            }

        } else if (strcmp(directive, "repeat") == 0) {
            char   *count_s = strtok(arg, " \t");
            char   *text = strtok(NULL, "");
            char   *stop;
            long    count;
            long    k;

            if (count_s == NULL || text == NULL) {
                die("%s:%d: repeat needs <count> <text>", file, lineno);
            }

            count = strtol(count_s, &stop, 10);

            /* The whole token has to be the number. "10junk" parsing as 10
             * would build a different request than the file describes, and a
             * size-driven case that silently changes size is exactly the way a
             * limit test stops reaching its limit. */
            if (stop == count_s || *stop != '\0') {
                die("%s:%d: repeat count \"%s\" is not a number",
                    file, lineno, count_s);
            }

            if (count < 1 || count > 100000) {
                die("%s:%d: repeat count %ld out of range (1..100000)",
                    file, lineno, count);
            }

            for (k = 0; k < count; k++) {
                append_escaped(&cases[n - 1].request, &cases[n - 1].request_len,
                               &cap, text);
            }

        } else if (strcmp(directive, "from") == 0) {
            cases[n - 1].source = xstrdup(trim(arg));

        } else if (strcmp(directive, "fault") == 0) {
            cases[n - 1].fault = xstrdup(trim(arg));

        } else if (strcmp(directive, "probe") == 0) {
            parse_assert(cases[n - 1].probes, &cases[n - 1].n_probes,
                         directive, trim(arg), file, lineno);

        } else if (strcmp(directive, "delta") == 0) {
            parse_assert(cases[n - 1].deltas, &cases[n - 1].n_deltas,
                         directive, trim(arg), file, lineno);

        } else {
            die("%s:%d: unknown directive \"%s\"", file, lineno, directive);
        }
    }

    fclose(fp);

    return n;
}
