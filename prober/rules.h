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
 *
 * `send` is repeatable and concatenates verbatim -- no implied CRLF, no
 * Content-Length synthesis, no header reordering -- so a stanza can spell out a
 * malformed request byte for byte. Escapes: \r \n \t \\ \" \0 \xNN.
 *
 * `repeat <count> <text>` appends its text N times, for the cases that need
 * kilobytes of filler to overrun a server limit without making the rule file
 * unreadable.
 */

#ifndef NGX_TEST_HARNESS_RULES_H
#define NGX_TEST_HARNESS_RULES_H

#include <stddef.h>

#define MAX_ASSERTS  32
#define MAX_CASES    256


typedef enum {
    EXPECT_STATUS,
    EXPECT_BODY_CONTAINS,
    EXPECT_HEADER_CONTAINS
} expect_kind;

typedef struct {
    expect_kind  kind;
    long         number;
    char        *text;
} expectation;

typedef struct {
    char  *path;
    char  *op;
    char  *literal;
} probe_assert;

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
