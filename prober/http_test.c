/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * http_test.c -- TAP self-test for response splitting and header search.
 *
 * http_parse_response() is exported precisely for this file: the inputs worth
 * testing -- no header terminator, a body that itself contains CRLFCRLF, an
 * embedded NUL, a truncated status line -- are the ones a live server will not
 * produce on demand, so testing through a socket would leave exactly the
 * interesting cases untested.
 *
 * Every fixture goes through parse_bytes(), which mimics what http_request()
 * hands the parser: a malloc'd buffer of raw_len bytes with a convenience NUL
 * after them. Length-bounded fixtures throughout -- several embed NULs, and
 * the point is that the parser counts bytes, not C strings.
 */

/* _GNU_SOURCE for the socket/clock/fork machinery the pacing fixtures need:
 * -std=c11 alone hides CLOCK_MONOTONIC and friends behind the POSIX guards. */
#define _GNU_SOURCE

#include "http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Bumped by hand: a test that vanishes should show up as a plan mismatch
 * rather than as a smaller green run. */
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
parse_bytes(http_response *resp, const char *bytes, size_t len)
{
    char  *buf = malloc(len + 1);

    if (buf == NULL) {
        fprintf(stderr, "http_test: out of memory\n");
        exit(2);
    }

    memcpy(buf, bytes, len);
    buf[len] = '\0';

    memset(resp, 0, sizeof(*resp));
    resp->raw = buf;
    resp->raw_len = len;

    http_parse_response(resp);
}


/* sizeof-1 only works on literals; a macro keeps the call sites honest about
 * that and spares every fixture a hand-counted length. */
#define PARSE(resp, lit)  parse_bytes(resp, lit, sizeof(lit) - 1)


/*
 * A `pause` is the one directive whose whole meaning is timing, so recording
 * the offsets in the parser proves nothing on its own -- write_request() has
 * to actually stall. These fixtures run a throwaway loopback server in a child
 * process, which reads the request and reports how long the bytes took to
 * arrive and what they were.
 *
 * Timing assertions are one-sided on purpose: the test asserts a floor (the
 * pause happened) and never a ceiling (it was not much longer), because a
 * loaded CI box can stretch any interval but cannot make a nanosleep return
 * early. A two-sided assertion here would be a flake generator.
 */
typedef struct {
    long    elapsed_ms;     /* time from first byte to complete request */
    char    got[256];
    size_t  got_len;
} echo_result;


/*
 * Serve exactly one connection on an ephemeral port, reading `want_len` bytes
 * and timing their arrival. The port is handed back through *port, the result
 * through a pipe, so the parent can connect without racing on a fixed port.
 */
static pid_t
spawn_echo(int *port, size_t want_len, int result_fd)
{
    int                 srv, one = 1;
    struct sockaddr_in  sin;
    socklen_t           slen = sizeof(sin);
    pid_t               pid;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "http_test: socket: %s\n", strerror(errno));
        exit(2);
    }

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind(srv, (struct sockaddr *) &sin, sizeof(sin)) != 0
        || listen(srv, 1) != 0
        || getsockname(srv, (struct sockaddr *) &sin, &slen) != 0)
    {
        fprintf(stderr, "http_test: listen: %s\n", strerror(errno));
        exit(2);
    }

    *port = ntohs(sin.sin_port);

    /* The listener is created before the fork so the parent knows the port is
     * already bound the moment spawn_echo() returns -- connecting cannot race
     * the child reaching accept(). */
    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "http_test: fork: %s\n", strerror(errno));
        exit(2);
    }

    if (pid == 0) {
        int              c = accept(srv, NULL, NULL);
        echo_result      r;
        struct timespec  t0, t1;
        size_t           len = 0;

        memset(&r, 0, sizeof(r));

        if (c < 0) {
            _exit(2);
        }

        clock_gettime(CLOCK_MONOTONIC, &t0);

        while (len < want_len && len < sizeof(r.got)) {
            ssize_t n = read(c, r.got + len, sizeof(r.got) - len);

            if (n <= 0) {
                break;
            }
            len += (size_t) n;
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);

        r.got_len = len;
        r.elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000
                       + (t1.tv_nsec - t0.tv_nsec) / 1000000L;

        /* Answer so the parent's read loop ends on a real response rather
         * than on its own timeout, which would add timeout_ms to every case.
         * Both writes are checked only to satisfy the warning wall: this is a
         * fixture child, and the parent already fails the case if the report
         * does not arrive intact. */
        if (write(c, "HTTP/1.1 200 OK\r\n\r\n", 19) < 0) {
            _exit(2);
        }

        close(c);

        if (write(result_fd, &r, sizeof(r)) != (ssize_t) sizeof(r)) {
            _exit(2);
        }

        _exit(0);
    }

    close(srv);

    return pid;
}


/*
 * Drive http_request() against the throwaway server and collect what it saw.
 * Returns 0 when the exchange and the report both completed.
 */
static int
run_echo(const unsigned char *req, size_t req_len,
         const http_pause *pauses, size_t n_pauses, echo_result *out)
{
    int            fds[2], port = 0;
    pid_t          pid;
    http_response  resp;
    char           errbuf[256];
    int            rc, st;

    if (pipe(fds) != 0) {
        return -1;
    }

    pid = spawn_echo(&port, req_len, fds[1]);
    close(fds[1]);

    rc = http_request("127.0.0.1", port, req, req_len, 5000, NULL,
                      pauses, n_pauses, &resp, errbuf, sizeof(errbuf));

    if (rc == 0) {
        http_response_free(&resp);
    }

    memset(out, 0, sizeof(*out));

    if (read(fds[0], out, sizeof(*out)) != (ssize_t) sizeof(*out)) {
        rc = -1;
    }

    close(fds[0]);
    waitpid(pid, &st, 0);

    return rc;
}


int
main(void)
{
    http_response  r;

    printf("1..%d\n", PLANNED);

    /* ---- splitting a well-formed response ----------------------------- */

    PARSE(&r, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello");
    ok(r.status == 200, "the status code is parsed");
    ok(r.headers != NULL
       && strcmp(r.headers, "HTTP/1.1 200 OK\r\nContent-Type: text/plain") == 0,
       "the header block ends before the terminator, no trailing CRLF");
    ok(r.body_len == 5 && r.body != NULL && memcmp(r.body, "hello", 5) == 0,
       "the body starts after the terminator");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 204 No Content\r\nServer: t\r\n\r\n");
    ok(r.body != NULL && r.body_len == 0,
       "an empty body is present with length zero, not missing");
    http_response_free(&r);

    /* ---- no header terminator ----------------------------------------- */

    /* A truncated response must not be guessed at: headers == NULL is the
     * signal that distinguishes a reset mid-headers from an empty reply. */
    PARSE(&r, "HTTP/1.1 200 OK\r\nContent-Ty");
    ok(r.headers == NULL, "no CRLFCRLF leaves headers NULL");
    ok(r.body == NULL && r.body_len == 0, "no CRLFCRLF leaves no body");
    ok(r.status == 200, "the status still parses without a terminator");
    http_response_free(&r);

    /* ---- bodies the framing must not trip over ------------------------ */

    PARSE(&r, "HTTP/1.1 200 OK\r\n\r\nfirst\r\n\r\nsecond");
    ok(r.body_len == 15 && memcmp(r.body, "first\r\n\r\nsecond", 15) == 0,
       "a body containing CRLFCRLF splits at the FIRST terminator");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 200 OK\r\n\r\nab\0cd");
    ok(r.body_len == 5 && r.body[2] == '\0' && memcmp(r.body, "ab\0cd", 5) == 0,
       "an embedded NUL in the body is counted, not terminating");
    http_response_free(&r);

    PARSE(&r, "\r\n\r\nbody");
    ok(r.headers != NULL && r.headers[0] == '\0' && r.body_len == 4,
       "a leading terminator yields an empty header block");
    http_response_free(&r);

    /* ---- status line edge cases --------------------------------------- */

    PARSE(&r, "HTTP/1.0 302 Found\r\n\r\n");
    ok(r.status == 302, "HTTP/1.0 parses like HTTP/1.1");
    http_response_free(&r);

    /* http.h promises -1 for anything unparseable. Bare strtol returns 0 here,
     * which a rule could match against a literal "0" status, so the end pointer
     * decides instead. */
    PARSE(&r, "HTTP/1.1 abc def\r\n\r\n");
    ok(r.status == -1, "a non-numeric status is unparseable, not 0");
    http_response_free(&r);

    /* The other side of that check: a real zero must still parse as zero. */
    PARSE(&r, "HTTP/1.1 0 Zero\r\n\r\n");
    ok(r.status == 0, "a literal 0 status is not confused with unparseable");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1_200_OK\r\n\r\n");
    ok(r.status == -1, "a response with no space anywhere has no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1  200 OK\r\n\r\n");
    ok(r.status == 200, "strtol skips a doubled space before the code");
    http_response_free(&r);

    /* The old ">12 bytes" guard existed only to make sure a status line
     * fragment had room for "HTTP/1.1 200". That magic number is gone: the
     * version-token walk itself proves there is a well-formed "HTTP/x.y "
     * prefix, and strtol needs only digits after it -- not a trailing space
     * or a byte count -- so a buffer that ends right after the code still
     * parses. Length is no longer what gates this; token well-formedness is. */
    PARSE(&r, "HTTP/1.1 200");
    ok(r.status == 200, "the buffer may end right after the code, no trailing byte needed");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 200 ");
    ok(r.status == 200, "a trailing space after the code also parses fine");
    http_response_free(&r);

    PARSE(&r, "SMTP/1.1 200 OK\r\nX: y\r\n\r\nbody");
    ok(r.status == -1, "a non-HTTP prefix yields no status");
    ok(r.headers != NULL && r.body_len == 4,
       "the header/body split does not depend on the status line");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1 99999999999999999999 OK\r\n\r\n");
    ok(r.headers != NULL,
       "a status far past the integer range still parses the response");
    http_response_free(&r);

    /* ---- malformed version tokens (the false-PASS class) --------------- */

    /* This is the exact defect: "HTTP/" matched, garbage after it, first
     * space in the buffer happened to precede a real-looking status. A rule
     * asserting status=200 against this must fail, not pass on garbage. */
    PARSE(&r, "HTTP/xyz 200 OK\r\n\r\n");
    ok(r.status == -1, "a non-numeric version token yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/ 200 OK\r\n\r\n");
    ok(r.status == -1, "an empty version token yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/1 200 OK\r\n\r\n");
    ok(r.status == -1, "a version with no '.' and no minor yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/1. 200 OK\r\n\r\n");
    ok(r.status == -1, "a '.' with no minor digits yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/.1 200 OK\r\n\r\n");
    ok(r.status == -1, "a '.' with no major digits yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/1.1x 200 OK\r\n\r\n");
    ok(r.status == -1,
       "trailing garbage fused onto the minor version yields no status");
    http_response_free(&r);

    PARSE(&r, "HTTP/2 200 OK\r\n\r\n");
    ok(r.status == -1,
       "a bare major-only \"HTTP/2\" (no minor) yields no status");
    http_response_free(&r);

    /* Multi-digit major/minor must still be accepted -- the token walk is
     * digit-run based, not single-digit. */
    PARSE(&r, "HTTP/10.99 200 OK\r\n\r\n");
    ok(r.status == 200, "multi-digit major.minor still parses");
    http_response_free(&r);

    /* A version token that runs off the end of the buffer with no space to
     * terminate it must not read past raw_len or parse a status. */
    PARSE(&r, "HTTP/1.1");
    ok(r.status == -1,
       "a version token with nothing past it yields no status");
    http_response_free(&r);

    /* An embedded NUL inside what would be the version token must not be
     * treated as a terminator or as a digit -- the scan is byte-counted
     * against raw_len, never a C-string scan. */
    PARSE(&r, "HTTP/1\0.1 200 OK\r\n\r\n");
    ok(r.status == -1, "an embedded NUL inside the version token yields no status");
    http_response_free(&r);

    /* ---- the empty and the absent ------------------------------------- */

    PARSE(&r, "");
    ok(r.status == -1 && r.headers == NULL && r.body == NULL,
       "an empty response parses to nothing without crashing");
    http_response_free(&r);

    memset(&r, 0, sizeof(r));
    http_parse_response(&r);
    ok(r.status == -1 && r.headers == NULL,
       "a NULL raw buffer parses to nothing without crashing");

    http_response_free(NULL);
    ok(1, "http_response_free tolerates NULL");

    PARSE(&r, "HTTP/1.1 200 OK\r\n\r\nx");
    http_response_free(&r);
    ok(r.raw == NULL && r.headers == NULL && r.body == NULL
       && r.raw_len == 0 && r.body_len == 0,
       "http_response_free clears every field it owns");

    /* ---- http_has_header ---------------------------------------------- */

    PARSE(&r, "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/plain\r\n"
              "X-Ban: active\r\n"
              "\r\n"
              "X-Body: not a header");

    ok(http_has_header(&r, "Content-Type: text/plain") == 1,
       "a whole header line matches");
    ok(http_has_header(&r, "content-TYPE") == 1,
       "the search is case-insensitive");
    ok(http_has_header(&r, "Type: text") == 1,
       "a substring within one line matches");
    ok(http_has_header(&r, "plain\r\nX-Ban") == 0,
       "a needle spanning two lines does not match across the CRLF");
    ok(http_has_header(&r, "X-Ban: active") == 1,
       "the last line matches without a trailing CRLF");
    ok(http_has_header(&r, "X-Body: not a header") == 0,
       "the body is not searched");
    ok(http_has_header(&r,
       "a needle longer than any single header line matches nothing") == 0,
       "a needle longer than every line does not match");

    /* An empty needle matches any non-empty header block. Odd, but pinned:
     * if this ever changes it should change on purpose, not by accident. */
    ok(http_has_header(&r, "") == 1,
       "an empty needle matches a non-empty header block");

    http_response_free(&r);

    memset(&r, 0, sizeof(r));
    ok(http_has_header(&r, "X-Ban") == 0,
       "a NULL header block matches nothing");

    PARSE(&r, "\r\n\r\nbody");
    ok(http_has_header(&r, "") == 0,
       "an empty needle does not match an empty header block");
    http_response_free(&r);

    /* ---- write_request pacing ------------------------------------------ */

    {
        static const unsigned char  req[] = "GET / HTTP/1.0\r\n\r\n";
        const size_t                req_len = sizeof(req) - 1;
        http_pause                  p[2];
        echo_result                 er;
        int                         rc;

        ok(run_echo(req, req_len, NULL, 0, &er) == 0
           && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0,
           "with no pauses the whole request arrives");

        /* The floor is deliberately below the requested 200 ms: coarse clocks
         * and scheduling can shave a few ms off the measured interval without
         * the pause having failed to happen. 150 still cannot be reached by a
         * write that never slept. */
        p[0].offset = 5;
        p[0].ms = 200;

        /* rc is kept rather than folded into the ok() expression: the next
         * case asserts over the SAME er, and a short-circuited `&&` would
         * leave it reading a struct from an exchange that never completed --
         * reporting a content mismatch when the real fault was the transfer. */
        rc = run_echo(req, req_len, p, 1, &er);

        ok(rc == 0 && er.elapsed_ms >= 150,
           "a pause delays the rest of the request by its duration");

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0,
           "a paused request still arrives byte-identical and in order");

        p[0].offset = 5;
        p[0].ms = 120;
        p[1].offset = 10;
        p[1].ms = 120;

        ok(run_echo(req, req_len, p, 2, &er) == 0 && er.elapsed_ms >= 180,
           "two pauses both delay, and their durations add up");

        /* An offset past the end must not walk off the buffer, and must still
         * send every byte -- the stall simply lands after the last one. */
        p[0].offset = req_len + 99;
        p[0].ms = 50;

        ok(run_echo(req, req_len, p, 1, &er) == 0
           && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0,
           "a pause offset past the end still sends the whole request");

        /* An offset-0 stall lands after connect() but before the first byte,
         * which is what makes a server's pre-request idle timeout reachable.
         * The fixture's clock starts at accept() -- which returns on the TCP
         * handshake, before any data -- so that leading stall IS inside the
         * measured window, and the request still arrives whole once it starts. */
        p[0].offset = 0;
        p[0].ms = 150;

        ok(run_echo(req, req_len, p, 1, &er) == 0
           && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0
           && er.elapsed_ms >= 100,
           "a pause at offset 0 stalls before the request, which still arrives whole");
    }

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        failures++;
    }

    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
