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
 *     pause   50
 *     send    Host: t\r\nConnection: close\r\n\r\n
 *     expect  status=403
 *     expect  body~Forbidden
 *     expect  header~Content-Type: text/html
 *     expect  raw_response_headers_like~^Content-Type:.*text
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
 * `pause <ms>` holds the connection open without writing for <ms>
 * milliseconds at the point it appears between `send` lines, so a rule can put
 * a request line on the wire and stall before its headers. That split is what
 * makes partial-header handling, request-header timeouts and smuggling
 * windows testable at all: a single write() hands the server a complete
 * request no matter how many `send` lines built it, because the bytes are
 * concatenated before they reach the socket. A `pause` before the first `send`
 * or after the last is accepted and stalls at that point (an opening stall
 * exercises the server's pre-request idle timeout; a trailing one holds the
 * connection open after a complete request). Bounded to 1..10000 ms per pause
 * and in sum, because a stall longer than the prober's read timeout would
 * report a harness timeout instead of the server behaviour under test.
 *
 * `repeat <count> <text>` appends its text N times, for the cases that need
 * kilobytes of filler to overrun a server limit without making the rule file
 * unreadable.
 *
 * `abort <offset>` writes the first <offset> bytes of the request and then
 * destroys the connection with a TCP reset (SO_LINGER{1,0}), so the server sees
 * ECONNRESET rather than a clean close. This is the client-vanishes-mid-request
 * primitive: it tests that a server releases a request's resources when the
 * peer disappears, instead of holding them until a timeout expires. Offset 0
 * resets before the first byte (connect-then-vanish); an offset past the
 * request end sends all of it and then resets. Pauses inside the written prefix
 * still apply, so `send_slow` followed by `abort` dribbles and then gives up --
 * a real slowloris client's exit.
 *
 * A reset case has NO response, so it may not carry `expect`, `expect_not` or
 * `error_code_like`: those would assert against an empty buffer, and an
 * `expect_not` in particular would pass unconditionally, reporting green for an
 * assertion that tested nothing. The parser rejects the combination at load
 * time. Judge an aborted case with `no_error_log` / `grep_error_log` / `probe`
 * / `delta` -- evidence the server itself produced. For the same reason `abort`
 * and `shutdown` are mutually exclusive: a half-close asks to be answered, a
 * reset says the client is gone.
 *
 * `expect raw_response_headers_like <regex>` asserts a POSIX extended regex
 * against the raw HTTP header block (colon-delimited lines with CRLF
 * terminators, no status line, no body).
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

#include "http.h"

#define MAX_ASSERTS  32
#define MAX_CASES    256
#define MAX_PAUSES   16

/* Upper bound on a single `pause`, and on the sum of a case's pauses. A rule
 * file that pauses longer than the prober's own read timeout would report a
 * harness timeout rather than the server behaviour under test, so the ceiling
 * is low enough to stay inside any plausible timeout. */
#define MAX_PAUSE_MS  10000

/* Upper bound on a `send_slow` chunk size. A chunk larger than the request is
 * merely a single write, so this only has to be big enough to be useful; the
 * cap exists to keep an obviously-wrong value (a typo'd byte count) from
 * silently degrading a pacing test into one plain write that still reports ok. */
#define MAX_SEND_SLOW_CHUNK  4096

/* Bounds on `recv_slow <chunk> <ms>`. The chunk shares send_slow's cap for the
 * same reason -- a chunk larger than the response is merely one read -- and the
 * stall shares the pause ceiling, since a receive-side stall spends the
 * prober's read timeout just as surely as a send-side one. The ceiling is per
 * READ here, not per case: the total depends on the response size, which the
 * rule file cannot know, so a rule that paces a large response can still exceed
 * the timeout and will report it as the harness timeout it is. */
#define MAX_RECV_SLOW_CHUNK  4096

/* Bounds on `so_rcvbuf <bytes>`. The floor is deliberately low -- the point is
 * a buffer small enough that a stalled reader is felt by the server -- and the
 * kernel silently raises anything under its own minimum, so a value below it is
 * a request for "as small as allowed" rather than an error. The ceiling only
 * rejects a typo'd value so large it would defeat the directive's purpose. */
#define MIN_RCVBUF  128
#define MAX_RCVBUF  1048576


/*
 * A case's `pause` list is kept beside the request buffer rather than
 * splitting the request into segments, so a case with no `pause` produces the
 * exact same single write() it did before this directive existed -- the wire
 * behaviour of every existing rule file is unchanged by construction, not by
 * testing. The element type belongs to the transport (http.h), which is what
 * turns an offset and a duration into actual wire timing.
 */


typedef enum {
    EXPECT_STATUS,
    EXPECT_BODY_CONTAINS,
    EXPECT_BODY_SHA256,
    EXPECT_HEADER_CONTAINS,
    EXPECT_NOT_BODY_CONTAINS,
    EXPECT_NOT_HEADER_CONTAINS,
    EXPECT_STATUS_LIKE,
    EXPECT_RAW_RESPONSE_HEADERS_LIKE
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
    http_pause      pauses[MAX_PAUSES];
    size_t          n_pauses;

    /* shutdown(2) mode applied once the request is written, or HTTP_SHUT_NONE.
     * Initialised to HTTP_SHUT_NONE when a stanza opens -- a zeroed field would
     * mean SHUT_RD, silently half-closing every case that never asked. */
    int             shut_how;

    /* Whether a shutdown directive was seen, tracked separately from the mode.
     * The duplicate check must not ask "is shut_how still the sentinel?": that
     * conflates "unset" with "set", and would break the moment HTTP_SHUT_NONE
     * were ever given a value a rule file can also spell. */
    int             saw_shutdown;

    /* Byte offset at which to reset the connection, or HTTP_ABORT_NONE.
     * Initialised to the sentinel when a stanza opens: offset 0 is a legitimate
     * value meaning "reset before writing anything", so a zeroed field would
     * abort every case that never asked -- the same trap as shut_how above, and
     * the reason the duplicate check keys on saw_abort rather than on the
     * offset still holding the sentinel. */
    size_t          abort_at;
    int             saw_abort;

    /* Milliseconds to hold the connection open, idle and unread, after the
     * request is written, or HTTP_HOLD_NONE. Zero is the off value -- holding
     * for no time is indistinguishable from not holding -- so like recv_opt
     * below this needs no sentinel, and saw_hold exists only to reject a case
     * that sets it twice. */
    long            hold_ms;
    int             saw_hold;

    /* Receive-side pacing and the client's SO_RCVBUF. Both zero by default,
     * which is "read as fast as the peer sends, system-default buffer" -- the
     * behaviour of every rule that predates these directives. Unlike the two
     * fields above, zero is genuinely the off value here, so neither needs a
     * sentinel or a saw_ flag for defaulting; the duplicate guards below exist
     * only to reject a case that sets one twice. */
    http_recv       recv_opt;
    int             saw_recv_slow;
    int             saw_rcvbuf;
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
