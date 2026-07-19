/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * http.h -- raw-socket HTTP client for the prober.
 *
 * Raw sockets on purpose. The cases worth testing here are the ones a well-
 * behaved client library refuses to emit: split writes, smuggled headers,
 * oversized request lines, invalid chunked framing, close mid-body. libcurl
 * would normalize exactly the malformation under test, so the request bytes
 * are written verbatim, byte for byte, as the rule file spells them.
 *
 * Responses are read to EOF, so every rule must ask the server to close
 * (Connection: close). That is a deliberate constraint rather than a missing
 * feature: keep-alive would require trusting the response framing this harness
 * exists to distrust.
 */

#ifndef PROBER_HTTP_H
#define PROBER_HTTP_H

#include <stddef.h>

/*
 * A stall in the middle of writing the request: once `offset` bytes have been
 * written, hold off for `ms` before writing the rest.
 *
 * Declared here rather than in rules.h because the transport owns the wire
 * behaviour and must not depend on the rule parser -- rules.c fills these in,
 * but http.c is what makes them mean anything, and http_test.c drives them
 * without a rule file in sight.
 */
typedef struct {
    size_t  offset;
    long    ms;
} http_pause;

typedef struct {
    int     status;         /* parsed status code, -1 if unparseable */
    char   *raw;            /* whole response, NUL-terminated for convenience */
    size_t  raw_len;        /* true length; raw may contain embedded NULs */
    char   *headers;        /* header block, NUL-terminated, no trailing CRLF */
    char   *body;           /* points into raw, after the header terminator */
    size_t  body_len;
} http_response;


/*
 * Connect to host:port, write req_len bytes verbatim, read until the peer
 * closes or timeout_ms elapses, and parse the status line.
 *
 * Returns 0 on success and fills *resp (caller frees with http_response_free).
 * Returns -1 on connect/write/read failure with *errbuf describing why; a
 * response that arrives but is malformed is success here with status -1,
 * because "the server answered garbage" is a test outcome, not a harness fault.
 */
/*
 * `source` optionally binds the client socket to a specific local address
 * before connecting. Anything in 127.0.0.0/8 is local, so rules can present
 * themselves as distinct peers -- which is what makes per-address ban
 * behaviour testable at all. Pass NULL for the default source.
 */
/*
 * `pauses` optionally splits the write: an entry {offset, ms} writes up to
 * `offset` bytes, sleeps `ms`, then continues. Entries must be sorted by
 * ascending offset; an offset of 0 stalls before the first byte and an offset
 * at or past req_len stalls after the last. Pass NULL / 0 to write the whole
 * request in one call, which is what every rule without a `pause` does.
 */
int http_request(const char *host, int port,
                 const unsigned char *req, size_t req_len,
                 int timeout_ms, const char *source,
                 const http_pause *pauses, size_t n_pauses,
                 http_response *resp,
                 char *errbuf, size_t errlen);

void http_response_free(http_response *resp);

/*
 * Split an already-received response into status / headers / body, in place.
 *
 * `resp->raw` and `resp->raw_len` must be set; every other field is written by
 * this call, and `body` points into `raw` rather than owning storage.
 *
 * Exposed so http_test.c can drive it over fixed byte strings. The interesting
 * inputs -- no header terminator, a body that itself contains CRLFCRLF, an
 * embedded NUL, a truncated status line -- are precisely the ones a live server
 * will not produce on demand, so testing this through a socket would leave the
 * cases that matter untested.
 */
void http_parse_response(http_response *resp);

/*
 * Case-insensitive search of the header block for a "Name: value" substring,
 * matched against each unfolded header line. Returns 1 on match.
 */
int http_has_header(const http_response *resp, const char *needle);

#endif /* PROBER_HTTP_H */
