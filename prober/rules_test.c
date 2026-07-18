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
#define PLANNED  53

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
