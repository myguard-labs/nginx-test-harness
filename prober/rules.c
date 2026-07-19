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

        if (tc->expects[i].kind == EXPECT_STATUS_LIKE
            || tc->expects[i].kind == EXPECT_RAW_RESPONSE_HEADERS_LIKE)
        {
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

    } else if (strncmp(arg, "body_sha256=", 12) == 0) {
        e->kind = EXPECT_BODY_SHA256;
        e->text = xstrdup(trim(arg + 12));

    } else if (strncmp(arg, "header~", 7) == 0) {
        e->kind = EXPECT_HEADER_CONTAINS;
        e->text = xstrdup(trim(arg + 7));

    } else if (strncmp(arg, "raw_response_headers_like~", 26) == 0) {
        char *pattern = trim(arg + 26);

        if (*pattern == '\0') {
            die("%s:%d: raw_response_headers_like~ needs a non-empty pattern",
                file, lineno);
        }

        e->kind = EXPECT_RAW_RESPONSE_HEADERS_LIKE;
        e->text = xstrdup(pattern);

        if (regcomp(&e->re, e->text, REG_EXTENDED) != 0) {
            die("%s:%d: invalid regex in raw_response_headers_like~: %.128s",
                file, lineno, pattern);
        }

    } else {
        die("%s:%d: unknown expect form \"%s\" "
            "(want status=, body~, body_sha256=, header~, raw_response_headers_like~)",
            file, lineno, arg);
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
 * Wall-clock cost of one pause entry that spans [offset, upto).
 *
 * A plain stall costs its `ms` once. For a paced entry, write_request() sleeps
 * once BEFORE the span and write_paced() sleeps BETWEEN chunks -- so N chunks
 * cost 1 + (N-1) sleeps, i.e. exactly N * ms. Mirror any change to either of
 * those two functions here: getting this wrong in the lenient direction is
 * what would let a rule file declare a dribble longer than the read timeout
 * and then report a harness timeout as if it were a server verdict.
 */
static long
pause_cost_ms_raw(size_t offset, size_t upto, size_t chunk, long ms)
{
    size_t  span, chunks;

    if (chunk == 0) {
        return ms;
    }

    span = upto > offset ? upto - offset : 0;

    if (span == 0) {
        return ms;                       /* the leading sleep still happens */
    }

    chunks = span / chunk + (span % chunk != 0);

    if (chunks > (size_t) (MAX_PAUSE_MS / (ms > 0 ? ms : 1)) + 1) {
        return MAX_PAUSE_MS + 1;         /* saturate rather than overflow */
    }

    return (long) chunks * ms;
}


static long
pause_cost_ms(const http_pause *p, size_t upto)
{
    return pause_cost_ms_raw(p->offset, upto, p->chunk, p->ms);
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
    size_t   n = 0, cap = 0, i;
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

            /* Not zero: SHUT_RD is 0, so leaving this at the memset default
             * would half-close every case that never asked for a shutdown. */
            cases[n - 1].shut_how = HTTP_SHUT_NONE;

            /* Likewise not zero: offset 0 means "reset before the first byte",
             * so the memset default would abort every case in the file. */
            cases[n - 1].abort_at = HTTP_ABORT_NONE;
            continue;
        }

        if (!open_case || n == 0) {
            die("%s:%d: \"%s\" before any name directive",
                file, lineno, directive);
        }

        if (strcmp(directive, "send") == 0) {
            append_escaped(&cases[n - 1].request, &cases[n - 1].request_len,
                           &cap, arg);

        } else if (strcmp(directive, "pause") == 0) {
            test_case  *tc = &cases[n - 1];
            char       *ms_s = trim(arg);
            char       *stop;
            long        ms;
            size_t      k;
            long        total = 0;

            if (*ms_s == '\0') {
                die("%s:%d: pause needs <ms>", file, lineno);
            }

            /* Same whole-token check as `repeat`: a pause that silently became
             * zero would turn a timing test into a plain request and still
             * report ok. */
            ms = strtol(ms_s, &stop, 10);

            if (stop == ms_s || *stop != '\0') {
                die("%s:%d: pause \"%s\" is not a number", file, lineno, ms_s);
            }

            if (ms < 1 || ms > MAX_PAUSE_MS) {
                die("%s:%d: pause %ld out of range (1..%d ms)",
                    file, lineno, ms, MAX_PAUSE_MS);
            }

            if (tc->n_pauses >= MAX_PAUSES) {
                die("%s:%d: too many pause directives (max %d)",
                    file, lineno, MAX_PAUSES);
            }

            for (k = 0; k < tc->n_pauses; k++) {
                total += tc->pauses[k].ms;
            }

            /* The prober's read timeout bounds the whole exchange, so a case
             * that stalls longer than that would report a harness timeout
             * rather than whatever the server did. Fail the rule file instead
             * of shipping a test that cannot mean what it says. */
            if (total + ms > MAX_PAUSE_MS) {
                die("%s:%d: pause total %ld ms exceeds the %d ms ceiling",
                    file, lineno, total + ms, MAX_PAUSE_MS);
            }

            tc->pauses[tc->n_pauses].offset = tc->request_len;
            tc->pauses[tc->n_pauses].ms = ms;
            tc->pauses[tc->n_pauses].chunk = 0;
            tc->n_pauses++;

        } else if (strcmp(directive, "send_slow") == 0) {
            test_case  *tc = &cases[n - 1];
            char       *rest = trim(arg);
            char       *stop;
            long        chunk, ms;
            size_t      k;
            long        total = 0;

            if (*rest == '\0') {
                die("%s:%d: send_slow needs <chunk> <ms>", file, lineno);
            }

            chunk = strtol(rest, &stop, 10);

            if (stop == rest || (*stop != ' ' && *stop != '\t')) {
                die("%s:%d: send_slow \"%s\" is not <chunk> <ms>",
                    file, lineno, rest);
            }

            if (chunk < 1 || chunk > MAX_SEND_SLOW_CHUNK) {
                die("%s:%d: send_slow chunk %ld out of range (1..%d bytes)",
                    file, lineno, chunk, MAX_SEND_SLOW_CHUNK);
            }

            rest = trim(stop);
            ms = strtol(rest, &stop, 10);

            if (stop == rest || *stop != '\0') {
                die("%s:%d: send_slow \"%s\" is not a number", file, lineno,
                    rest);
            }

            if (ms < 1 || ms > MAX_PAUSE_MS) {
                die("%s:%d: send_slow %ld out of range (1..%d ms)",
                    file, lineno, ms, MAX_PAUSE_MS);
            }

            if (tc->n_pauses >= MAX_PAUSES) {
                die("%s:%d: too many pause/send_slow directives (max %d)",
                    file, lineno, MAX_PAUSES);
            }

            for (k = 0; k < tc->n_pauses; k++) {
                total += pause_cost_ms(&tc->pauses[k],
                                       k + 1 < tc->n_pauses
                                           ? tc->pauses[k + 1].offset
                                           : tc->request_len);
            }

            /* A paced entry costs ms per chunk, not ms once. Charging it as a
             * single pause would let a rule file declare a dribble that blows
             * through the read timeout and then reports a harness timeout
             * instead of whatever the server did -- the exact failure the
             * plain-pause ceiling exists to prevent. The bytes this entry will
             * pace are not known until the case closes, so cost it against the
             * request as it stands and re-check at close. */
            total += pause_cost_ms_raw(tc->request_len, tc->request_len,
                                       (size_t) chunk, ms);

            if (total > MAX_PAUSE_MS) {
                die("%s:%d: send_slow pushes the case to %ld ms, over the "
                    "%d ms ceiling", file, lineno, total, MAX_PAUSE_MS);
            }

            tc->pauses[tc->n_pauses].offset = tc->request_len;
            tc->pauses[tc->n_pauses].ms = ms;
            tc->pauses[tc->n_pauses].chunk = (size_t) chunk;
            tc->n_pauses++;

        } else if (strcmp(directive, "shutdown") == 0) {
            test_case  *tc = &cases[n - 1];
            char       *how_s = trim(arg);
            char       *stop;
            long        how;

            if (*how_s == '\0') {
                die("%s:%d: shutdown needs 0|1|2", file, lineno);
            }

            how = strtol(how_s, &stop, 10);

            if (stop == how_s || *stop != '\0') {
                die("%s:%d: shutdown \"%s\" is not a number",
                    file, lineno, how_s);
            }

            if (how < 0 || how > 2) {
                die("%s:%d: shutdown %ld out of range (0=RD, 1=WR, 2=RDWR)",
                    file, lineno, how);
            }

            /* One per case: two shutdowns would make the second a no-op at
             * best and contradict the first at worst, and silently keeping the
             * last would let a rule file read as if both applied. Keyed on a
             * dedicated flag rather than on shut_how still holding the
             * sentinel, so the check stays correct however that value is
             * chosen. */
            if (tc->saw_shutdown) {
                die("%s:%d: a case may carry only one shutdown directive",
                    file, lineno);
            }

            /* The other half of the abort/shutdown exclusion; see the abort
             * directive below for why the two cannot both apply. */
            if (tc->saw_abort) {
                die("%s:%d: abort and shutdown are mutually exclusive",
                    file, lineno);
            }

            tc->shut_how = (int) how;
            tc->saw_shutdown = 1;

        } else if (strcmp(directive, "abort") == 0) {
            test_case  *tc = &cases[n - 1];
            char       *off_s = trim(arg);
            char       *stop;
            long        off;

            if (*off_s == '\0') {
                die("%s:%d: abort needs <offset>", file, lineno);
            }

            off = strtol(off_s, &stop, 10);

            if (stop == off_s || *stop != '\0') {
                die("%s:%d: abort \"%s\" is not a number", file, lineno, off_s);
            }

            /* Zero is allowed -- reset before the first byte -- but negative is
             * not, and would otherwise wrap into an enormous size_t that reads
             * as "never abort", turning a reset case into an ordinary request
             * that still reports ok. */
            if (off < 0) {
                die("%s:%d: abort offset %ld is negative", file, lineno, off);
            }

            if (tc->saw_abort) {
                die("%s:%d: a case may carry only one abort directive",
                    file, lineno);
            }

            /* A half-close says "I have finished sending, answer me"; a reset
             * says "I am gone". Applying both would send a FIN the reset then
             * invalidates, so the case would test neither directive cleanly.
             * Checked in both directions below, since either may come first. */
            if (tc->saw_shutdown) {
                die("%s:%d: abort and shutdown are mutually exclusive",
                    file, lineno);
            }

            /* The other half of the recv_slow exclusion; see that directive. */
            if (tc->saw_recv_slow) {
                die("%s:%d: recv_slow and abort are mutually exclusive",
                    file, lineno);
            }

            tc->abort_at = (size_t) off;
            tc->saw_abort = 1;

        } else if (strcmp(directive, "recv_slow") == 0) {
            test_case  *tc = &cases[n - 1];
            char       *rest = trim(arg);
            char       *stop;
            long        chunk, ms;

            if (*rest == '\0') {
                die("%s:%d: recv_slow needs <chunk> <ms>", file, lineno);
            }

            chunk = strtol(rest, &stop, 10);

            if (stop == rest || (*stop != ' ' && *stop != '\t')) {
                die("%s:%d: recv_slow \"%s\" is not <chunk> <ms>",
                    file, lineno, rest);
            }

            if (chunk < 1 || chunk > MAX_RECV_SLOW_CHUNK) {
                die("%s:%d: recv_slow chunk %ld out of range (1..%d bytes)",
                    file, lineno, chunk, MAX_RECV_SLOW_CHUNK);
            }

            rest = trim(stop);
            ms = strtol(rest, &stop, 10);

            if (stop == rest || *stop != '\0') {
                die("%s:%d: recv_slow \"%s\" is not a number", file, lineno,
                    rest);
            }

            if (ms < 1 || ms > MAX_PAUSE_MS) {
                die("%s:%d: recv_slow %ld out of range (1..%d ms)",
                    file, lineno, ms, MAX_PAUSE_MS);
            }

            if (tc->saw_recv_slow) {
                die("%s:%d: a case may carry only one recv_slow directive",
                    file, lineno);
            }

            /* Pacing reads on a case that resets the connection is incoherent:
             * abort tears the socket down before the response is read at all,
             * so the pacing would apply to nothing. Silently allowing it would
             * let a rule file read as though it tested backpressure. */
            if (tc->saw_abort) {
                die("%s:%d: recv_slow and abort are mutually exclusive",
                    file, lineno);
            }

            tc->recv_opt.chunk = (size_t) chunk;
            tc->recv_opt.ms = ms;
            tc->saw_recv_slow = 1;

        } else if (strcmp(directive, "so_rcvbuf") == 0) {
            test_case  *tc = &cases[n - 1];
            char       *sz_s = trim(arg);
            char       *stop;
            long        sz;

            if (*sz_s == '\0') {
                die("%s:%d: so_rcvbuf needs <bytes>", file, lineno);
            }

            sz = strtol(sz_s, &stop, 10);

            if (stop == sz_s || *stop != '\0') {
                die("%s:%d: so_rcvbuf \"%s\" is not a number",
                    file, lineno, sz_s);
            }

            if (sz < MIN_RCVBUF || sz > MAX_RCVBUF) {
                die("%s:%d: so_rcvbuf %ld out of range (%d..%d bytes)",
                    file, lineno, sz, MIN_RCVBUF, MAX_RCVBUF);
            }

            if (tc->saw_rcvbuf) {
                die("%s:%d: a case may carry only one so_rcvbuf directive",
                    file, lineno);
            }

            tc->recv_opt.rcvbuf = (int) sz;
            tc->saw_rcvbuf = 1;

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

    /*
     * Re-check pause budgets now that every request buffer is final.
     *
     * A `send_slow` entry paces from its own offset to the NEXT entry's offset
     * (or the end of the request), so its true cost is not known while the
     * stanza is still open -- any `send` line after it adds bytes to dribble.
     * The check at parse time can only see the request so far, so it catches
     * an obviously-oversized value early with a line number; this pass is what
     * actually enforces the ceiling. Done over all cases rather than at each
     * stanza-close so neither close path (blank line, EOF) can skip it.
     */
    for (i = 0; i < n; i++) {
        test_case  *tc = &cases[i];
        long        total = 0;
        size_t      k;

        /*
         * An aborted connection is reset before the server can answer, so there
         * is no response for a status/body/header assertion to read. Left
         * alone, such an expectation would evaluate against an empty buffer:
         * `expect body~foo` would fail for a reason that has nothing to do with
         * the server, and `expect_not body~foo` would PASS unconditionally,
         * reporting green for an assertion that never tested anything. That
         * second case is why this is a load-time die() rather than a runtime
         * skip -- a silently vacuous assertion is worse than a missing one.
         *
         * What remains meaningful on an aborted case is evidence the server
         * itself produced: no_error_log / grep_error_log, and the probe and
         * delta counters. Those are exactly the assertions this directive
         * exists to serve -- did the worker log the reset, and did it release
         * the request's resources -- so the case is left with the checks that
         * can actually observe the behaviour under test.
         */
        if (tc->saw_abort && tc->n_expects > 0) {
            die("%s: case \"%s\" carries an abort directive and %zu response "
                "expectation(s); a reset connection has no response to assert "
                "on -- use no_error_log / grep_error_log / probe / delta "
                "instead", file,
                tc->name != NULL ? tc->name : "(unnamed)", tc->n_expects);
        }

        for (k = 0; k < tc->n_pauses; k++) {
            size_t  upto = k + 1 < tc->n_pauses ? tc->pauses[k + 1].offset
                                                : tc->request_len;

            total += pause_cost_ms(&tc->pauses[k], upto);

            if (total > MAX_PAUSE_MS) {
                die("%s: case \"%s\" stalls %ld ms in total, over the %d ms "
                    "ceiling", file,
                    tc->name != NULL ? tc->name : "(unnamed)",
                    total, MAX_PAUSE_MS);
            }
        }
    }

    return n;
}
