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
#define PLANNED  65

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
    size_t  reads;          /* successful read() calls that returned bytes */
    size_t  max_read;       /* largest single read, in bytes */
    int     saw_eof;        /* the client half-closed: read() returned 0 */

    /* The client reset the connection: read() failed with ECONNRESET rather
     * than reporting a clean EOF. This is the ONLY observable that separates an
     * `abort` from an ordinary close -- both end the connection, and the byte
     * count the server managed to read is identical either way. Recording the
     * offset in the parser proves nothing about the wire. */
    int     saw_reset;
} echo_result;


/*
 * Serve exactly one connection on an ephemeral port, reading `want_len` bytes
 * and timing their arrival. The port is handed back through *port, the result
 * through a pipe, so the parent can connect without racing on a fixed port.
 */
static pid_t
spawn_echo(int *port, size_t want_len, int want_eof, int result_fd)
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

            if (n < 0) {
                /* ECONNRESET here is the abort case's whole signal, so it is
                 * recorded rather than treated as a fixture failure. */
                if (errno == ECONNRESET) {
                    r.saw_reset = 1;
                }
                break;
            }

            if (n == 0) {
                break;
            }

            /* Read counts are indicative, not exact: TCP may coalesce two
             * writes into one read or split one write across two, so tests
             * assert loose bounds (more than one read, no read larger than the
             * chunk) rather than an exact segment count. With TCP_NODELAY and
             * a pace far longer than loopback latency, those bounds are still
             * decisive -- a single unpaced write cannot satisfy them. */
            r.reads++;

            if ((size_t) n > r.max_read) {
                r.max_read = (size_t) n;
            }

            len += (size_t) n;
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);

        /*
         * One more read, to distinguish "the client sent its request and is
         * waiting for a reply" from "the client half-closed". Only done when
         * the caller asked (want_eof), because without a shutdown this read
         * blocks until the socket timeout and would add that to every case.
         *
         * This is what makes a SHUT_WR assertion mean anything: recording the
         * mode in the parser proves nothing about the wire, and the response
         * still arrives either way, so EOF here is the only observable that
         * distinguishes the two.
         */
        if (want_eof) {
            char            scratch[16];
            ssize_t         n;
            struct timeval  rtv;

            /* Bounded, because the no-shutdown case deliberately reaches this
             * read with the client still open: without a timeout it would sit
             * here until the parent tore the connection down, making the
             * negative assertion depend on teardown order rather than on the
             * shutdown. A timeout leaves saw_eof at 0, which is exactly the
             * "still open" verdict that case asserts. */
            rtv.tv_sec = 0;
            rtv.tv_usec = 300000;
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));

            do {
                n = read(c, scratch, sizeof(scratch));
            } while (n < 0 && errno == EINTR);

            if (n == 0) {
                r.saw_eof = 1;
            }

            /* Same read serves the abort cases: when the client wrote its whole
             * prefix, the loop above ended on the byte count rather than on the
             * reset, so the reset is only observable here. EOF and reset are
             * mutually exclusive outcomes of that one read, which is precisely
             * the distinction the abort tests assert on. */
            if (n < 0 && errno == ECONNRESET) {
                r.saw_reset = 1;
            }
        }

        r.got_len = len;
        r.elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000
                       + (t1.tv_nsec - t0.tv_nsec) / 1000000L;

        /*
         * Answer so the parent's read loop ends on a real response rather
         * than on its own timeout, which would add timeout_ms to every case.
         *
         * MSG_NOSIGNAL because the abort cases reach here with the connection
         * already reset: a plain write() to a reset socket raises SIGPIPE,
         * whose default action would kill this child BEFORE it reports through
         * the pipe. The parent would then see a short read and fail the case as
         * a fixture error -- an abort test that can never pass, for a reason
         * having nothing to do with the code under test.
         *
         * A failed send is therefore not fatal here: on an aborted connection
         * there is no peer left to answer, and the report below is the only
         * thing the parent actually needs.
         */
        (void) send(c, "HTTP/1.1 200 OK\r\n\r\n", 19, MSG_NOSIGNAL);

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
run_echo_full(const unsigned char *req, size_t req_len,
              const http_pause *pauses, size_t n_pauses, int shut_how,
              size_t abort_at, int want_eof, echo_result *out)
{
    int            fds[2], port = 0;
    pid_t          pid;
    http_response  resp;
    char           errbuf[256];
    int            rc, st;

    if (pipe(fds) != 0) {
        return -1;
    }

    pid = spawn_echo(&port, req_len, want_eof, fds[1]);
    close(fds[1]);

    rc = http_request("127.0.0.1", port, req, req_len, 5000, NULL,
                      pauses, n_pauses, shut_how, abort_at, &resp, errbuf,
                      sizeof(errbuf));

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


/* The common case: no shutdown, no abort, so the cases that predate those
 * directives read exactly as they did. */
static int
run_echo(const unsigned char *req, size_t req_len,
         const http_pause *pauses, size_t n_pauses, echo_result *out)
{
    return run_echo_full(req, req_len, pauses, n_pauses, HTTP_SHUT_NONE,
                         HTTP_ABORT_NONE, 0, out);
}


static int
run_echo_shut(const unsigned char *req, size_t req_len,
              const http_pause *pauses, size_t n_pauses, int shut_how,
              int want_eof, echo_result *out)
{
    return run_echo_full(req, req_len, pauses, n_pauses, shut_how,
                         HTTP_ABORT_NONE, want_eof, out);
}


/*
 * Drive an aborting request. `want_len` is passed separately from req_len
 * because the client writes only the prefix before the reset: telling the
 * fixture to expect the whole request would leave its read loop blocked on
 * bytes that are never sent, and the reset would be observed by the timeout
 * rather than by the read. want_eof is always on -- the extra read is what
 * turns the reset into ECONNRESET rather than an unnoticed teardown.
 */
static int
run_echo_abort(const unsigned char *req, size_t req_len, size_t want_len,
               const http_pause *pauses, size_t n_pauses, size_t abort_at,
               echo_result *out)
{
    int            fds[2], port = 0;
    pid_t          pid;
    http_response  resp;
    char           errbuf[256];
    int            rc, st;

    if (pipe(fds) != 0) {
        return -1;
    }

    pid = spawn_echo(&port, want_len, 1, fds[1]);
    close(fds[1]);

    rc = http_request("127.0.0.1", port, req, req_len, 5000, NULL,
                      pauses, n_pauses, HTTP_SHUT_NONE, abort_at, &resp,
                      errbuf, sizeof(errbuf));

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
        /* Zeroed so `chunk` is 0 (plain stall) in every case that does not set
         * it -- an uninitialized chunk would turn the pause cases into pacing
         * cases at random. */
        http_pause                  p[2] = {{0, 0, 0}, {0, 0, 0}};
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

        /*
         * send_slow: pace the whole request in 8-byte chunks, 10 ms apart.
         *
         * req_len is 18, so this is 3 chunks: one leading sleep, then two
         * BETWEEN the three chunks (none after the last). The fixture's clock
         * starts at accept(), which can return after the leading sleep is
         * already underway, so only the two inter-chunk sleeps are reliably
         * inside the measured window -- the floor is 20 ms, not 30. Measuring
         * against the nominal 30 leaves no margin at all: gcc lands on 30-31
         * and clang+ASan on 29, which is a broken test rather than a real
         * regression. The floor still cannot be reached by a write that never
         * slept, and case 52's chunk bound covers segmentation separately.
         */
        p[0].offset = 0;
        p[0].ms = 10;
        p[0].chunk = 8;

        rc = run_echo(req, req_len, p, 1, &er);

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0,
           "a paced request arrives byte-identical and in order");

        ok(rc == 0 && er.reads > 1 && er.max_read <= 8,
           "send_slow splits the request into chunks no larger than asked");

        ok(rc == 0 && er.elapsed_ms >= 20,
           "send_slow paces the chunks apart in time");

        /* A chunk at or above the request length degrades to one write, but
         * still honours the leading sleep -- the pacing knob must not become a
         * way to accidentally skip the stall it was configured with. */
        p[0].offset = 0;
        p[0].ms = 120;
        p[0].chunk = 4096;

        rc = run_echo(req, req_len, p, 1, &er);

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0
           && er.elapsed_ms >= 80,
           "a chunk larger than the request is one write after the stall");

        /* Pacing that starts partway in: the first 10 bytes go out at once,
         * then the remainder dribbles. This is the shape a slowloris rule
         * actually uses -- a complete request line, then a slow header block. */
        p[0].offset = 10;
        p[0].ms = 10;
        p[0].chunk = 4;

        rc = run_echo(req, req_len, p, 1, &er);

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0
           && er.reads > 1,
           "send_slow can begin partway through the request");

        p[0].chunk = 0;

        /*
         * shutdown SHUT_WR half-closes the sending side once the request is
         * out. The response still arrives -- that is the whole point, and it
         * is also why the response alone cannot prove the shutdown happened.
         * The fixture's extra read is the observable: it sees EOF instead of
         * blocking, which only happens if the client really half-closed.
         */
        rc = run_echo_shut(req, req_len, NULL, 0, SHUT_WR, 1, &er);

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0,
           "a half-closed request still arrives whole");

        ok(rc == 0 && er.saw_eof,
           "shutdown SHUT_WR reaches the server as EOF");

        /* Without the directive the client stays open, so the same fixture
         * must NOT see EOF -- otherwise the assertion above would pass for a
         * connection that merely closed on its own. */
        rc = run_echo_shut(req, req_len, NULL, 0, HTTP_SHUT_NONE, 1, &er);

        ok(rc == 0 && er.got_len == req_len && !er.saw_eof,
           "without shutdown the sending side stays open");
    }

    /*
     * abort resets the connection after a prefix of the request.
     *
     * Two independent things have to hold, and testing only the first is the
     * trap: the server must receive exactly the prefix (not the whole request),
     * AND the connection must end in a RESET rather than an ordinary close. A
     * plain close would also truncate the request and would also satisfy a byte
     * count -- so without the ECONNRESET assertion, a version of this directive
     * that forgot SO_LINGER entirely would still report green.
     */
    {
        static const unsigned char  req[] =
            "GET /slow HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\nBODY";
        size_t                      req_len = sizeof(req) - 1;
        echo_result                 er;
        http_pause                  p[1];
        int                         rc;

        rc = run_echo_abort(req, req_len, 20, NULL, 0, 20, &er);

        ok(rc == 0 && er.got_len == 20 && memcmp(er.got, req, 20) == 0,
           "abort sends exactly the bytes before its offset");

        ok(rc == 0 && er.saw_reset,
           "abort reaches the server as ECONNRESET, not a clean close");

        /* The negative control for the assertion above: the same fixture, the
         * same byte count, no abort. It must NOT see a reset -- otherwise
         * saw_reset would be measuring the fixture's own teardown rather than
         * the directive. */
        rc = run_echo_full(req, 20, NULL, 0, HTTP_SHUT_NONE,
                           HTTP_ABORT_NONE, 1, &er);

        ok(rc == 0 && er.got_len == 20 && !er.saw_reset,
           "without abort the connection ends without a reset");

        /* Offset 0 is a real value, not "unset": the connection is reset before
         * a single request byte goes out. This is the case a zeroed abort_at
         * field would inflict on every rule in the file. */
        rc = run_echo_abort(req, req_len, 1, NULL, 0, 0, &er);

        ok(rc == 0 && er.got_len == 0,
           "abort 0 resets before writing any request bytes");

        /* An offset past the end writes everything and then resets, rather
         * than clamping to something shorter or refusing outright. */
        rc = run_echo_abort(req, req_len, req_len, NULL, 0, req_len + 500, &er);

        ok(rc == 0 && er.got_len == req_len
           && memcmp(er.got, req, req_len) == 0 && er.saw_reset,
           "an abort offset past the request end sends all of it, then resets");

        /*
         * Pauses inside the written prefix still apply: this is the
         * slowloris-then-give-up shape, and it is the combination most likely
         * to break if the abort path were bolted on by skipping write_request()
         * rather than by shortening what it is asked to write.
         */
        p[0].offset = 0;
        p[0].ms = 30;
        p[0].chunk = 8;

        rc = run_echo_abort(req, req_len, 24, p, 1, 24, &er);

        ok(rc == 0 && er.got_len == 24 && er.reads > 1,
           "send_slow paces the prefix an abort then truncates");

        ok(rc == 0 && er.elapsed_ms >= 25,
           "the paced prefix before an abort is actually paced");
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
