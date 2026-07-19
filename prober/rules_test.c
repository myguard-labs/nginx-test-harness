/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * rules_test.c -- TAP self-test for the rule-file parser.
 *
 * load_rules() decides the exact bytes that go on the wire. A defect here does
 * not fail a test -- it silently tests something other than what the rule file
 * says, and the run still reports ok. So the cases below pin byte-exact
 * decoding (escapes, embedded NULs, repeat expansion, trailing spaces) and
 * verify that every malformed rule file is rejected up front rather than
 * parsed into something the author did not write.
 *
 * die() exits the process, so rejection cases run load_rules() in a fork()ed
 * child and assert on the exit status (util's die exits 2). The child's stdio
 * is pointed at /dev/null first: die() prints its reason to stderr, and the
 * inherited stdout buffer would otherwise replay the parent's TAP lines when
 * exit() flushes it.
 */

/* mkstemp(), fork(), waitpid() are POSIX, not C11, and the build asks for
 * -std=c11 strictly -- same dance as util.c. */
#define _GNU_SOURCE

#include "rules.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Bumped by hand: a test that vanishes should show up as a plan mismatch
 * rather than as a smaller green run. */
#define PLANNED  106

static int  tests_run = 0;
static int  failures = 0;

static test_case  cases[MAX_CASES];


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
free_all(size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        case_free(&cases[i]);
    }
}


/*
 * load_rules() reads a file, not a string, so every fixture takes a trip
 * through a temp file. The file is unlinked as soon as it has been consumed;
 * a failure between mkstemp and unlink leaks at most one file in $TMPDIR.
 */
static const char *
write_tmp(const char *text)
{
    static char  path[512];
    const char  *tmpdir = getenv("TMPDIR");
    int          fd;
    size_t       len = strlen(text);

    if (tmpdir == NULL || *tmpdir == '\0') {
        tmpdir = "/tmp";
    }

    snprintf(path, sizeof(path), "%s/rules_test.XXXXXX", tmpdir);

    fd = mkstemp(path);
    if (fd < 0) {
        die("mkstemp %s failed", path);
    }

    if (write(fd, text, len) != (ssize_t) len) {
        die("short write to %s", path);
    }

    close(fd);

    return path;
}


static size_t
load_str(const char *text)
{
    const char  *path = write_tmp(text);
    size_t       n;

    n = load_rules(path, cases, MAX_CASES);
    unlink(path);

    return n;
}


static void
die_on_path(const char *path, size_t max, const char *name)
{
    pid_t  pid;
    int    st;

    /* Without the flush, the child's copy of the stdout buffer still holds
     * every TAP line printed so far, and die()'s exit() would replay them. */
    fflush(stdout);

    pid = fork();
    if (pid < 0) {
        die("fork failed");
    }

    if (pid == 0) {
        if (freopen("/dev/null", "w", stdout) == NULL
            || freopen("/dev/null", "w", stderr) == NULL)
        {
            _exit(99);
        }

        load_rules(path, cases, max);
        _exit(0);                      /* parsed fine: the test below fails */
    }

    /* An interrupted wait leaves st indeterminate, so the assertion below would
     * read uninitialised stack rather than the child's exit status. */
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) {
            die("waitpid failed");
        }
    }

    ok(WIFEXITED(st) && WEXITSTATUS(st) == 2, name);
}


static void
expect_die(const char *text, const char *name)
{
    const char  *path = write_tmp(text);

    die_on_path(path, MAX_CASES, name);
    unlink(path);
}


/*
 * Byte-exact check of what a stanza's send/repeat lines put in the request
 * buffer. memcmp against an explicit length, never strcmp: several fixtures
 * embed NUL bytes on purpose, and the whole point is that the parser counts
 * them.
 */
static void
send_bytes_are(const char *body, const char *want, size_t want_len,
               const char *name)
{
    char    text[4096];
    size_t  n;
    int     good;

    snprintf(text, sizeof(text), "name t\n%s\n", body);

    n = load_str(text);

    good = (n == 1
            && cases[0].request_len == want_len
            && cases[0].request != NULL
            && memcmp(cases[0].request, want, want_len) == 0);

    if (!good) {
        printf("# %s: %zu cases, request_len %zu (want %zu)\n",
               name, n, n > 0 ? cases[0].request_len : 0, want_len);
    }

    ok(good, name);
    free_all(n);
}


int
main(void)
{
    size_t  n;

    printf("1..%d\n", PLANNED);

    /* ---- escape decoding ---------------------------------------------- */

    send_bytes_are("send a\\r\\n\\tb", "a\r\n\tb", 5,
                   "\\r \\n \\t decode to their control bytes");
    send_bytes_are("send \\\\\\\"", "\\\"", 2,
                   "\\\\ and \\\" decode to backslash and quote");
    send_bytes_are("send a\\0b", "a\0b", 3,
                   "an embedded \\0 is counted, not string-terminated");
    send_bytes_are("send \\x41\\x6a", "Aj", 2,
                   "two-digit hex escapes, either case");
    send_bytes_are("send \\xAq", "\nq", 2,
                   "a one-digit hex escape stops at the first non-hex byte");
    send_bytes_are("send \\xA", "\n", 1,
                   "a one-digit hex escape at end of line is complete");
    send_bytes_are("send a\\", "a\\", 2,
                   "a trailing lone backslash is a literal backslash");

    expect_die("name t\nsend \\xzz\n", "\\x with no hex digits dies");
    expect_die("name t\nsend a\\x\n", "\\x at end of line dies");
    expect_die("name t\nsend \\q\n", "an unknown escape dies");

    /* ---- send concatenation and whitespace ---------------------------- */

    /* Leading whitespace after the directive is eaten by the line splitter,
     * so a send line cannot start with a literal space -- that is the
     * documented reason \x20 exists. Pin both halves of that contract. */
    send_bytes_are("send GET\nsend  /x", "GET/x", 5,
                   "send lines concatenate with no implied separator");
    send_bytes_are("send \\x20x", " x", 2,
                   "a leading space must be spelled \\x20");
    send_bytes_are("send ab  ", "ab  ", 4,
                   "trailing spaces in a send line are preserved");

    /* ---- repeat ------------------------------------------------------- */

    send_bytes_are("repeat 3 ab", "ababab", 6,
                   "repeat appends count copies");
    send_bytes_are("repeat 2 \\r\\n", "\r\n\r\n", 4,
                   "repeat decodes escapes in its text");
    send_bytes_are("send X\nrepeat 2 y", "Xyy", 3,
                   "repeat appends after earlier send lines");

    n = load_str("name t\nrepeat 100000 x\n");
    ok(n == 1 && cases[0].request_len == 100000,
       "repeat at the upper bound builds the full length");
    free_all(n);

    expect_die("name t\nrepeat 10junk x\n",
               "a repeat count with trailing junk dies");
    expect_die("name t\nrepeat 0 x\n", "repeat 0 dies");
    expect_die("name t\nrepeat -1 x\n", "a negative repeat count dies");
    expect_die("name t\nrepeat 100001 x\n",
               "a repeat count over the bound dies");
    expect_die("name t\nrepeat 10\n", "repeat with no text dies");

    /* ---- pause --------------------------------------------------------- */

    /* The offset is what makes a pause mean anything: it has to land on the
     * byte count written so far, not on the send-line index, or the stall
     * happens somewhere other than where the rule file drew the split. */
    n = load_str("name t\nsend AB\npause 5\nsend CD\n");
    ok(n == 1 && cases[0].n_pauses == 1
       && cases[0].pauses[0].offset == 2 && cases[0].pauses[0].ms == 5,
       "pause records the byte offset of the split and its duration");
    free_all(n);

    n = load_str("name t\nsend AB\npause 5\nsend CD\n");
    ok(n == 1 && cases[0].request_len == 4
       && memcmp(cases[0].request, "ABCD", 4) == 0,
       "pause does not change the bytes of the request");
    free_all(n);

    n = load_str("name t\nsend AB\npause 5\npause 7\nsend CD\n");
    ok(n == 1 && cases[0].n_pauses == 2
       && cases[0].pauses[0].offset == 2 && cases[0].pauses[0].ms == 5
       && cases[0].pauses[1].offset == 2 && cases[0].pauses[1].ms == 7,
       "two pauses at the same point both record");
    free_all(n);

    n = load_str("name t\npause 5\nsend AB\n");
    ok(n == 1 && cases[0].n_pauses == 1 && cases[0].pauses[0].offset == 0,
       "a pause before any send stalls at offset 0");
    free_all(n);

    n = load_str("name t\nsend AB\npause 5\n");
    ok(n == 1 && cases[0].n_pauses == 1 && cases[0].pauses[0].offset == 2,
       "a trailing pause stalls after the last byte");
    free_all(n);

    n = load_str("name t\nsend AB\n");
    ok(n == 1 && cases[0].n_pauses == 0,
       "a case with no pause directive records none");
    free_all(n);

    /* Offsets must come out ascending; write_request() walks them in order and
     * would write backwards on an unsorted list. */
    n = load_str("name t\nsend AB\npause 5\nsend CD\npause 6\nsend EF\n");
    ok(n == 1 && cases[0].n_pauses == 2
       && cases[0].pauses[0].offset == 2 && cases[0].pauses[1].offset == 4,
       "pause offsets are recorded in ascending order");
    free_all(n);

    expect_die("name t\npause\n", "pause with no argument dies");
    expect_die("name t\npause 5junk\n",
               "a pause duration with trailing junk dies");
    expect_die("name t\npause 0\n", "pause 0 dies");
    expect_die("name t\npause -1\n", "a negative pause dies");
    expect_die("name t\npause 10001\n", "a pause over the ceiling dies");
    expect_die("name t\npause 6000\npause 6000\n",
               "pauses summing over the ceiling die");
    expect_die("name t\npause 1\npause 1\npause 1\npause 1\npause 1\npause 1\n"
               "pause 1\npause 1\npause 1\npause 1\npause 1\npause 1\npause 1\n"
               "pause 1\npause 1\npause 1\npause 1\n",
               "more than MAX_PAUSES pause directives die");

    /* ---- stanza framing ----------------------------------------------- */

    n = load_str("");
    ok(n == 0, "an empty file parses to zero cases");
    free_all(n);

    n = load_str("# comment\n\n   \n# more\n");
    ok(n == 0, "comments and blank lines alone parse to zero cases");
    free_all(n);

    n = load_str("name first\nsend a\n\nname second\nsend b\n");
    ok(n == 2
       && strcmp(cases[0].name, "first") == 0
       && strcmp(cases[1].name, "second") == 0,
       "a blank line separates stanzas");
    free_all(n);

    n = load_str("name   padded name  \nsend a\n");
    ok(n == 1 && strcmp(cases[0].name, "padded name") == 0,
       "a case name is trimmed");
    free_all(n);

    n = load_str("name t\nsend a\n# interleaved comment\nsend b\n");
    ok(n == 1 && cases[0].request_len == 2
       && memcmp(cases[0].request, "ab", 2) == 0,
       "a comment does not end a stanza");
    free_all(n);

    n = load_str("name t\n   # indented comment\nsend a\n");
    ok(n == 1 && cases[0].request_len == 1,
       "an indented comment is still a comment");
    free_all(n);

    expect_die("send a\n", "a directive before any name dies");
    expect_die("name t\nsend a\n   \nsend b\n",
               "a whitespace-only line ends the stanza");
    expect_die("name t\nfrobnicate x\n", "an unknown directive dies");

    {
        const char  *path =
            write_tmp("name a\nsend x\n\nname b\nsend x\n\nname c\nsend x\n");

        die_on_path(path, 2, "more cases than the caller's max dies");
        unlink(path);
    }

    {
        char  text[4096];
        int   i, off;

        off = snprintf(text, sizeof(text), "name t\n");
        for (i = 0; i < MAX_ASSERTS + 1; i++) {
            off += snprintf(text + off, sizeof(text) - (size_t) off,
                            "expect status=200\n");
        }

        expect_die(text, "one expect line past MAX_ASSERTS dies");

        off = snprintf(text, sizeof(text), "name t\n");
        for (i = 0; i < MAX_ASSERTS; i++) {
            off += snprintf(text + off, sizeof(text) - (size_t) off,
                            "probe n == 1\n");
        }

        n = load_str(text);
        ok(n == 1 && cases[0].n_probes == MAX_ASSERTS,
           "exactly MAX_ASSERTS probe lines still load");
        free_all(n);
    }

    /* ---- expect parsing ----------------------------------------------- */

    n = load_str("name t\nexpect status=200\n");
    ok(n == 1 && cases[0].n_expects == 1
       && cases[0].expects[0].kind == EXPECT_STATUS
       && cases[0].expects[0].number == 200,
       "expect status= parses the number");
    free_all(n);

    /* -1 is the prober's own "unparseable" convention; the rule syntax does
     * not forbid asserting on it, so pin that it loads rather than dies. */
    n = load_str("name t\nexpect status=-1\n");
    ok(n == 1 && cases[0].expects[0].number == -1,
       "expect status=-1 is accepted");
    free_all(n);

    n = load_str("name t\nexpect body~hello\n");
    ok(n == 1 && cases[0].expects[0].kind == EXPECT_BODY_CONTAINS
       && strcmp(cases[0].expects[0].text, "hello") == 0,
       "expect body~ stores its needle");
    free_all(n);

    n = load_str("name t\nexpect header~X-Test: on\n");
    ok(n == 1 && cases[0].expects[0].kind == EXPECT_HEADER_CONTAINS
       && strcmp(cases[0].expects[0].text, "X-Test: on") == 0,
       "expect header~ keeps the colon and inner spaces");
    free_all(n);

    n = load_str("name t\nexpect body~hi   \n");
    ok(n == 1 && strcmp(cases[0].expects[0].text, "hi") == 0,
       "an expect needle is trimmed where a send line is not");
    free_all(n);

    expect_die("name t\nexpect status=200junk\n",
               "expect status= with trailing junk dies");
    expect_die("name t\nexpect status=\n", "expect status= with no number dies");
    expect_die("name t\nexpect claims~x\n", "an unknown expect form dies");

    /* ---- probe / delta ------------------------------------------------ */

    n = load_str("name t\nprobe zone.nodes == 1\n");
    ok(n == 1 && cases[0].n_probes == 1
       && strcmp(cases[0].probes[0].path, "zone.nodes") == 0
       && strcmp(cases[0].probes[0].op, "==") == 0
       && strcmp(cases[0].probes[0].literal, "1") == 0,
       "probe splits into path, op and literal");
    free_all(n);

    n = load_str("name t\ndelta fds == 0\n");
    ok(n == 1 && cases[0].n_deltas == 1
       && strcmp(cases[0].deltas[0].path, "fds") == 0,
       "delta parses like probe into its own list");
    free_all(n);

    n = load_str("name t\nprobe zone.name ~ demo zone  \n");
    ok(n == 1 && strcmp(cases[0].probes[0].literal, "demo zone") == 0,
       "a probe literal keeps inner spaces and drops trailing ones");
    free_all(n);

    n = load_str("name t\nprobe zone.name ~ demo\n");
    ok(n == 1 && cases[0].n_probes == 1,
       "probe accepts the substring operator");
    free_all(n);

    expect_die("name t\nprobe fds = 0\n", "an unknown operator dies");
    expect_die("name t\ndelta zone.name ~ x\n",
               "delta with the substring operator dies");
    expect_die("name t\nprobe fds\n", "probe with only a path dies");
    expect_die("name t\nprobe fds == \t\n",
               "probe with a whitespace-only literal dies");

    /* ---- expect_not parsing -------------------------------------------- */

    n = load_str("name t\nexpect_not body~oops\n");
    ok(n == 1 && cases[0].n_expects == 1
       && cases[0].expects[0].kind == EXPECT_NOT_BODY_CONTAINS
       && strcmp(cases[0].expects[0].text, "oops") == 0,
       "expect_not body~ parses to the negated body kind");
    free_all(n);

    n = load_str("name t\nexpect_not header~X-Debug\n");
    ok(n == 1 && cases[0].expects[0].kind == EXPECT_NOT_HEADER_CONTAINS
       && strcmp(cases[0].expects[0].text, "X-Debug") == 0,
       "expect_not header~ parses to the negated header kind");
    free_all(n);

    n = load_str("name t\nexpect_not body~  hi  \n");
    ok(n == 1 && strcmp(cases[0].expects[0].text, "hi") == 0,
       "an expect_not needle is trimmed like expect's");
    free_all(n);

    n = load_str("name t\nexpect body~a\nexpect_not body~b\n");
    ok(n == 1 && cases[0].n_expects == 2
       && cases[0].expects[0].kind == EXPECT_BODY_CONTAINS
       && cases[0].expects[1].kind == EXPECT_NOT_BODY_CONTAINS,
       "expect and expect_not coexist in one stanza");
    free_all(n);

    expect_die("name t\nexpect_not body~\n",
               "expect_not body~ with an empty pattern dies");
    expect_die("name t\nexpect_not header~   \n",
               "expect_not header~ with a whitespace-only pattern dies");
    expect_die("name t\nexpect_not status=200\n",
               "expect_not has no status= form and dies");
    expect_die("name t\nexpect_not claims~x\n",
               "an unknown expect_not form dies");
    expect_die("name t\nexpect_not\n",
               "expect_not with no argument at all dies");

    /* ---- error_code_like parsing ---------------------------------------- */

    n = load_str("name t\nerror_code_like ^2[0-9]{2}$\n");
    ok(n == 1 && cases[0].n_expects == 1
       && cases[0].expects[0].kind == EXPECT_STATUS_LIKE
       && strcmp(cases[0].expects[0].text, "^2[0-9]{2}$") == 0,
       "error_code_like compiles and stores its source pattern");
    free_all(n);

    n = load_str("name t\nerror_code_like   ^(4|5)[0-9]{2}$   \n");
    ok(n == 1 && strcmp(cases[0].expects[0].text, "^(4|5)[0-9]{2}$") == 0,
       "error_code_like trims surrounding whitespace, not the regex itself");
    free_all(n);

    n = load_str("name t\nerror_code_like .\n");
    ok(n == 1, "a trivial one-byte regex compiles");
    free_all(n);

    expect_die("name t\nerror_code_like\n",
               "error_code_like with no pattern dies");
    expect_die("name t\nerror_code_like    \n",
               "error_code_like with a whitespace-only pattern dies");
    expect_die("name t\nerror_code_like [unclosed\n",
               "an unterminated bracket expression dies");
    expect_die("name t\nerror_code_like (unclosed\n",
               "an unbalanced group dies");
    expect_die("name t\nerror_code_like *nostart\n",
               "a pattern starting with a repetition operator dies");

    /* ---- xfail parsing --------------------------------------------------- */

    n = load_str("name t\nxfail\nsend a\n");
    ok(n == 1 && cases[0].xfail == 1 && cases[0].xfail_reason == NULL,
       "a bare xfail sets the flag with no reason");
    free_all(n);

    n = load_str("name t\nxfail known broken until #42\nsend a\n");
    ok(n == 1 && cases[0].xfail == 1
       && cases[0].xfail_reason != NULL
       && strcmp(cases[0].xfail_reason, "known broken until #42") == 0,
       "xfail stores a trimmed reason");
    free_all(n);

    n = load_str("name t\nxfail   padded reason   \nsend a\n");
    ok(n == 1 && strcmp(cases[0].xfail_reason, "padded reason") == 0,
       "an xfail reason is trimmed on both ends");
    free_all(n);

    n = load_str("name a\nsend x\n\nname b\nxfail\nsend y\n");
    ok(n == 2 && cases[0].xfail == 0 && cases[1].xfail == 1,
       "xfail applies only to the stanza it appears in");
    free_all(n);

    expect_die("name t\nxfail\nxfail\n",
               "a duplicate xfail in one stanza dies");
    expect_die("xfail\nname t\nsend a\n",
               "xfail before any name directive dies");

    /* ---- no_error_log / grep_error_log parsing ------------------------- */

    n = load_str("name t\nno_error_log \\[emerg\\]\n");
    ok(n == 1 && cases[0].n_no_logs == 1
       && strcmp(cases[0].no_logs[0].pattern, "\\[emerg\\]") == 0,
       "no_error_log compiles and stores its source pattern");
    free_all(n);

    n = load_str("name t\ngrep_error_log banned by rule\n");
    ok(n == 1 && cases[0].n_grep_logs == 1
       && strcmp(cases[0].grep_logs[0].pattern, "banned by rule") == 0,
       "grep_error_log keeps inner spaces in its pattern");
    free_all(n);

    n = load_str("name t\nno_error_log a\ngrep_error_log b\nno_error_log c\n");
    ok(n == 1 && cases[0].n_no_logs == 2 && cases[0].n_grep_logs == 1,
       "no_error_log and grep_error_log accumulate independently");
    free_all(n);

    n = load_str("name t\nno_error_log   pad  \n");
    ok(n == 1 && strcmp(cases[0].no_logs[0].pattern, "pad") == 0,
       "a log pattern is trimmed on both ends");
    free_all(n);

    expect_die("name t\nno_error_log\n",
               "no_error_log with no pattern dies");
    expect_die("name t\ngrep_error_log    \n",
               "grep_error_log with a whitespace-only pattern dies");
    expect_die("name t\nno_error_log [unclosed\n",
               "no_error_log with an invalid regex dies");
    expect_die("name t\ngrep_error_log (unclosed\n",
               "grep_error_log with an invalid regex dies");

    {
        char  text[4096];
        int   i, off;

        off = snprintf(text, sizeof(text), "name t\n");
        for (i = 0; i < MAX_ASSERTS + 1; i++) {
            off += snprintf(text + off, sizeof(text) - (size_t) off,
                            "no_error_log x\n");
        }

        expect_die(text, "one no_error_log past MAX_ASSERTS dies");
    }

    /* ---- raw_response_headers_like parsing ----------------------------- */

    n = load_str("name t\nexpect raw_response_headers_like~^Content-Type: text\n");
    ok(n == 1 && cases[0].n_expects == 1
       && cases[0].expects[0].kind == EXPECT_RAW_RESPONSE_HEADERS_LIKE
       && strcmp(cases[0].expects[0].text, "^Content-Type: text") == 0,
       "raw_response_headers_like~ parses and stores its regex pattern");
    free_all(n);

    n = load_str("name t\nexpect raw_response_headers_like~  Content-Type  \n");
    ok(n == 1 && strcmp(cases[0].expects[0].text, "Content-Type") == 0,
       "raw_response_headers_like~ trims surrounding whitespace");
    free_all(n);

    n = load_str("name t\nexpect raw_response_headers_like~[a-z]+\n");
    ok(n == 1,
       "a valid regex in raw_response_headers_like~ compiles");
    free_all(n);

    expect_die("name t\nexpect raw_response_headers_like~\n",
               "raw_response_headers_like~ with no pattern dies");
    expect_die("name t\nexpect raw_response_headers_like~    \n",
               "raw_response_headers_like~ with whitespace-only pattern dies");
    expect_die("name t\nexpect raw_response_headers_like~[unclosed\n",
               "raw_response_headers_like~ with an invalid regex dies");
    expect_die("name t\nexpect raw_response_headers_like~(unclosed\n",
               "raw_response_headers_like~ with an unbalanced group dies");

    /* ---- from / fault ------------------------------------------------- */

    n = load_str("name t\nfrom  127.0.0.9 \nfault  fault_slab=3 \n");
    ok(n == 1 && strcmp(cases[0].source, "127.0.0.9") == 0,
       "from stores a trimmed source address");
    ok(strcmp(cases[0].fault, "fault_slab=3") == 0,
       "fault stores a trimmed probe query");
    free_all(n);

    /* ---- the file itself ---------------------------------------------- */

    die_on_path("/nonexistent/rules_test.does-not-exist", MAX_CASES,
                "an unopenable rule file dies");

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        failures++;
    }

    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
