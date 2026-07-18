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

#include "http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bumped by hand: a test that vanishes should show up as a plan mismatch
 * rather than as a smaller green run. */
#define PLANNED  44

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

    if (tests_run != PLANNED) {
        printf("# ran %d tests but the plan says %d\n", tests_run, PLANNED);
        failures++;
    }

    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
