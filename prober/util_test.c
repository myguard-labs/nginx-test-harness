/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * util_test.c -- TAP self-test for xstrtol().
 *
 * xstrtol() replaced atoi() on the -p and -t flags, and it exists for one
 * reason: atoi() reports a conversion error the same way it reports a genuine
 * zero. `-p http` became port 0 and `-t junk` became a 0 ms timeout, which is
 * SO_RCVTIMEO's "block indefinitely" -- so a typo'd flag hung the run or reded
 * every case while pointing nowhere near the flag that caused it.
 *
 * That makes the REJECTIONS the interesting half of this file. A validator that
 * accepts everything still passes any test that only feeds it valid input, so
 * most of what follows checks that malformed values are refused rather than
 * quietly converted.
 *
 * xstrtol() dies rather than returning an error, so the rejection cases cannot
 * be called in-process: die() exits. Each one runs in a fork and the parent
 * asserts on the child's exit status (2, per util.h) and on the message it
 * printed. Testing the status alone would pass on a crash, which is why the
 * message is checked too.
 */

#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Bumped by hand: a test that vanishes should show up as a plan mismatch
 * rather than as a smaller green run. */
#define PLANNED  14

static int  tests_run = 0;
static int  failures = 0;


static void
ok(int cond, const char *name)
{
    tests_run++;

    if (cond) {
        printf("ok %d - %s\n", tests_run, name);
    } else {
        printf("not ok %d - %s\n", tests_run, name);
        failures++;
    }
}


/*
 * Run xstrtol(s) in a child and report how it died.
 *
 * Returns the child's exit status, with the child's stderr captured into `msg`
 * so the caller can assert the diagnostic actually names the problem. A child
 * that is killed by a signal reports 128+signo, which no legitimate path
 * produces, so a crash cannot be mistaken for a clean rejection.
 */
static int
run_child(const char *s, const char *what, char *msg, size_t msglen)
{
    int    pipefd[2];
    int    status;
    pid_t  pid;

    msg[0] = '\0';

    if (pipe(pipefd) != 0) {
        return -1;
    }

    /*
     * Flush before forking. stdout is a pipe under `prove`, so it is fully
     * buffered: the TAP printed so far is still sitting in the parent's buffer,
     * the child inherits a copy of it, and the child's _exit()/die() path
     * flushes that copy too -- emitting every preceding line a second time, once
     * per fork. The run still exits 0, so the symptom is not a failure, it is a
     * TAP stream with duplicate plans that a harness either mis-counts or
     * rejects outright.
     */
    fflush(stdout);
    fflush(stderr);

    pid = fork();

    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        (void) xstrtol(s, what);

        /* Reached only if xstrtol returned where it should have died. Exit 0
         * so the parent's "expected 2" assertion fails loudly. */
        _exit(0);
    }

    close(pipefd[1]);

    /*
     * Drain to EOF rather than reading once.
     *
     * A single read() returns whatever one chunk is available and the close()
     * that followed it left the child writing into a pipe with no reader --
     * SIGPIPE, so the child died of signal 13 (reported here as 141) BEFORE
     * die() could exit 2, and the assertion below saw a crash instead of a
     * clean rejection. It only bit when the message was long enough or the
     * scheduler unlucky enough for the child to still be writing, which made it
     * flaky rather than dead: 2 runs in 5. Reading to EOF means the child is
     * never writing into a closed pipe.
     */
    {
        size_t   used = 0;
        ssize_t  n;

        while (used + 1 < msglen
               && (n = read(pipefd[0], msg + used, msglen - 1 - used)) > 0)
        {
            used += (size_t) n;
        }

        msg[used] = '\0';
    }

    close(pipefd[0]);
    waitpid(pid, &status, 0);

    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }

    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}


static void
rejects(const char *s, const char *expect_substr, const char *name)
{
    char  msg[512];
    int   status = run_child(s, "-t", msg, sizeof(msg));

    if (status != 2) {
        printf("# expected exit 2, got %d for input \"%s\"\n",
               status, s ? s : "(null)");
        ok(0, name);
        return;
    }

    if (strstr(msg, expect_substr) == NULL) {
        printf("# message did not mention \"%s\": %s\n", expect_substr, msg);
        ok(0, name);
        return;
    }

    ok(1, name);
}


int
main(void)
{
    printf("1..%d\n", PLANNED);

    /* The values that must be accepted, returned exactly. */
    ok(xstrtol("0", "-t") == 0, "zero parses");
    ok(xstrtol("1", "-t") == 1, "one parses");
    ok(xstrtol("18099", "-p") == 18099, "a port parses");
    ok(xstrtol("-5", "-t") == -5, "a negative value parses");
    ok(xstrtol("007", "-t") == 7, "leading zeros are decimal, not octal");
    ok(xstrtol("  12", "-t") == 12, "strtol's leading-space skip is preserved");

    /*
     * The rejections. "10junk" is the case that motivated this: atoi() returns
     * 10 and discards the rest, so a rule file or flag that says 10junk builds
     * a request the author did not write.
     */
    rejects("junk", "is not a number", "a non-numeric token is refused");
    rejects("10junk", "is not a number", "trailing garbage is refused");
    rejects("", "empty", "an empty value is refused");
    rejects(NULL, "empty", "a NULL value is refused");
    rejects("12 34", "is not a number", "an embedded space is refused");
    rejects("0x10", "is not a number", "hex is refused (base is 10, not 0)");

    /*
     * ERANGE. atoi() has undefined behaviour here; strtol saturates at
     * LONG_MAX/LONG_MIN and sets errno, which is the only reason this is
     * distinguishable from a legitimate huge value.
     */
    rejects("99999999999999999999999", "out of range",
            "a value past LONG_MAX is refused");
    rejects("-99999999999999999999999", "out of range",
            "a value past LONG_MIN is refused");

    if (tests_run != PLANNED) {
        printf("# planned %d tests but ran %d\n", PLANNED, tests_run);
        return 1;
    }

    return failures == 0 ? 0 : 1;
}
