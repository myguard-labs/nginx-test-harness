/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * rules.h -- the rule-file parser: text in, test cases out.
 *
 * Split out of prober.c so it can be exercised as a pure function by
 * rules_test.c. This parser decides the exact bytes that go on the wire, so a
 * defect here does not fail a test -- it silently tests something other than
 * what the rule file says, which no amount of running the suite would reveal.
 *
 * Rule file syntax -- one case per stanza, blank line separated:
 *
 *     name    ban arms after the configured count
 *     send    GET /guarded?id=1+union+select+1,2,3-- HTTP/1.1\r\n
 *     send    Host: t\r\nConnection: close\r\n\r\n
 *     expect  status=403
 *     expect  body~Forbidden
 *     expect  header~Content-Type: text/html
 *     probe   zone.nodes == 1
 *     delta   fds == 0
 *     from    127.0.0.9
 *     fault   fault_slab=1
 *     expect_not      body~Internal Server Error
 *     error_code_like ^(2|3)[0-9]{2}$
 *     xfail   known broken until #42 lands
 *
 * `send` is repeatable and concatenates verbatim -- no implied CRLF, no
 * Content-Length synthesis, no header reordering -- so a stanza can spell out a
 * malformed request byte for byte. Escapes: \r \n \t \\ \" \0 \xNN.
 *
 * `repeat <count> <text>` appends its text N times, for the cases that need
 * kilobytes of filler to overrun a server limit without making the rule file
 * unreadable.
 *
 * `expect_not` mirrors `expect` (`body~`, `header~`) but asserts the opposite:
 * the case fails if the pattern IS found. A distinct directive rather than a
 * `!~` operator on `expect`, so a rule file reads its polarity at the
 * directive name instead of a symbol easy to misread in a diff.
 *
 * `error_code_like <regex>` is `expect status=` generalised to a POSIX
 * extended regex against the status code rendered as decimal text (e.g.
 * "404"), for cases that accept a class of codes ("any 2xx") rather than one
 * exact value. Compiled at load time so a malformed pattern is a load-time
 * die(), not a run-time surprise on the one case that reaches it.
 *
 * `xfail [reason]` marks the whole case as a known failure: it still runs and
 * is still reported, but a failing xfail case does not fail the suite (TAP
 * `not ok N # TODO <reason>`), and a PASSING xfail case is flagged distinctly
 * (`ok N # TODO <reason>` -- TAP's convention for "this unexpectedly started
 * working"), because that is the signal that the annotation should be removed.
 *
 * `no_error_log <regex>` / `grep_error_log <regex>` assert over the server
 * error-log lines written DURING this case only: no line may match / at least
 * one line must match the POSIX extended regex. The prober records the log
 * file's size immediately before the case's request and evaluates only the
 * bytes appended after that mark -- grep-the-slice, not scrape-the-whole-log,
 * so an earlier case's lines can neither satisfy a grep_error_log nor trip a
 * no_error_log. Both need the log path (prober -e, or PROBER_ERROR_LOG, which
 * run.sh exports); a case carrying either directive FAILS when the path is
 * not configured, because a silently skipped assertion reads as a pass.
 * These are per-case and complement run.sh's whole-run alert/crit/emerg gate,
 * which stays authoritative for severities no rule thought to mention.
 */

#ifndef NGX_TEST_HARNESS_RULES_H
#define NGX_TEST_HARNESS_RULES_H

#include <regex.h>
#include <stddef.h>

#define MAX_ASSERTS  32
#define MAX_CASES    256


typedef enum {
    EXPECT_STATUS,
    EXPECT_BODY_CONTAINS,
    EXPECT_HEADER_CONTAINS,
    EXPECT_NOT_BODY_CONTAINS,
    EXPECT_NOT_HEADER_CONTAINS,
    EXPECT_STATUS_LIKE
} expect_kind;

typedef struct {
    expect_kind  kind;
    long         number;
    char        *text;
    regex_t      re;         /* compiled only for EXPECT_STATUS_LIKE */
} expectation;

typedef struct {
    char  *path;
    char  *op;
    char  *literal;
} probe_assert;

/* One no_error_log / grep_error_log line. The pattern source text is kept
 * beside the compiled form purely for diagnostics: a failure must be able to
 * say WHICH regex missed or matched, and regex_t cannot be printed. */
typedef struct {
    char     *pattern;
    regex_t   re;
} log_assert;

typedef struct {
    char           *name;
    char           *fault;      /* probe query armed before the send, or NULL */
    char           *source;     /* local address to connect from, or NULL     */
    unsigned char  *request;
    size_t          request_len;
    expectation     expects[MAX_ASSERTS];
    size_t          n_expects;
    probe_assert    probes[MAX_ASSERTS];
    size_t          n_probes;
    probe_assert    deltas[MAX_ASSERTS];   /* asserted on after minus before */
    size_t          n_deltas;
    int             xfail;      /* 1 if the case is annotated `xfail`        */
    char           *xfail_reason;  /* text after `xfail`, or NULL            */
    log_assert      no_logs[MAX_ASSERTS];    /* no line may match            */
    size_t          n_no_logs;
    log_assert      grep_logs[MAX_ASSERTS];  /* some line must match         */
    size_t          n_grep_logs;
} test_case;


/*
 * Parse `file` into `cases`, at most `max` of them. Returns the number parsed.
 * Any syntax error is fatal via die(): a rule file that does not say what its
 * author meant must not run at all, because a case that silently parses into
 * something else still reports ok.
 */
size_t load_rules(const char *file, test_case *cases, size_t max);

void case_free(test_case *tc);

#endif /* NGX_TEST_HARNESS_RULES_H */
