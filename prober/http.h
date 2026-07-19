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
 * `chunk` turns the stall into a paced dribble instead of a single stop: when
 * non-zero, the bytes from this entry's offset up to the next entry's offset
 * (or the end of the request) go out `chunk` bytes at a time with `ms` between
 * writes, which is the slowloris primitive. Zero means the plain single stall.
 *
 * Declared here rather than in rules.h because the transport owns the wire
 * behaviour and must not depend on the rule parser -- rules.c fills these in,
 * but http.c is what makes them mean anything, and http_test.c drives them
 * without a rule file in sight.
 */
typedef struct {
    size_t  offset;
    long    ms;
    size_t  chunk;
} http_pause;

typedef struct {
    int     status;         /* parsed status code, -1 if unparseable */
    char   *raw;            /* whole response, NUL-terminated for convenience */
    size_t  raw_len;        /* true length; raw may contain embedded NULs */
    char   *headers;        /* header block, NUL-terminated, no trailing CRLF */
    char   *body;           /* points into raw, after the header terminator */
    size_t  body_len;

    /* read() calls that returned bytes while collecting this response.
     *
     * Exposed because it is the only externally visible consequence of the
     * client's SO_RCVBUF: Linux never fails that setsockopt, it silently clamps
     * whatever it is given, so "was the option applied?" cannot be answered
     * from a return code -- only from the response arriving in more, smaller
     * reads. Diagnostic elsewhere; load-bearing in http_test.c. */
    size_t  reads;
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
/*
 * `shut_how` optionally calls shutdown(2) once the request is on the wire:
 * SHUT_WR (1) half-closes the sending side, which is what tells a server
 * reading to EOF that the body is complete without tearing the connection
 * down -- the response still arrives normally. SHUT_RD (0) and SHUT_RDWR (2)
 * are accepted for completeness, but a rule using them is asserting on what
 * the server logged, not on a response it will not see. Pass HTTP_SHUT_NONE
 * (-1) to leave the connection alone, which is what every rule without a
 * `shutdown` directive does.
 */
#define HTTP_SHUT_NONE  (-1)

/*
 * `abort_at` optionally destroys the connection with a TCP reset once that many
 * request bytes are on the wire, instead of completing the exchange. Setting
 * SO_LINGER{on, 0} makes close(2) emit RST rather than FIN, so the server sees
 * ECONNRESET on its next read: the request is not merely incomplete, the peer
 * is gone, and no response can be written to a socket that no longer exists.
 *
 * That is a different code path from every other directive here. `pause` and
 * `send_slow` stall a connection the server may still answer on; `shutdown`
 * half-closes one it will still answer on. A reset removes the answer entirely,
 * which is what makes it the primitive for testing that a server releases a
 * request's resources when the client vanishes mid-body rather than holding
 * them until a timeout expires.
 *
 * Because there is no response, this call SKIPS the read loop and returns
 * success with resp->status -1 and an empty body. A case using this must judge
 * the server from evidence the server itself produced -- its error log, or the
 * probe/delta counters -- never from a response. rules.c enforces that at parse
 * time, since an `expect status=` on an aborted case would otherwise assert
 * against an empty buffer and report a result that means nothing.
 *
 * An offset of 0 is meaningful and distinct from "unset": it resets the
 * connection before a single request byte is written, which is the
 * connect-then-vanish case. Pass HTTP_ABORT_NONE to complete the exchange
 * normally, which is what every rule without an `abort` directive does.
 */
#define HTTP_ABORT_NONE  ((size_t) -1)

/*
 * Receive-side pacing: read `chunk` bytes, hold off `ms`, repeat.
 *
 * This is the mirror of send_slow, and it tests the opposite half of the
 * server. A client that stops draining its socket is applying BACKPRESSURE: the
 * server's send buffer fills, its write() blocks or returns EAGAIN, and the
 * request sits half-written while the event loop must keep the connection alive
 * without spinning on it or leaking what it has buffered. That path is not
 * reachable from the sending side at all -- a module can handle every malformed
 * request correctly and still wedge a worker on a slow reader.
 *
 * `rcvbuf` sets SO_RCVBUF on the client socket, and the two only work as a
 * pair. With the default receive buffer the kernel happily absorbs an entire
 * modest response, so the pacing delays when this process SEES the bytes but
 * the server never blocks and nothing is under test. A small buffer is what
 * makes the stall reach the far end. Zero leaves the system default.
 *
 * Note the kernel doubles the requested SO_RCVBUF for bookkeeping and enforces
 * its own floor, so the effective size is not the number passed here; this asks
 * for "small", not for an exact byte count, and no assertion should depend on
 * the precise value.
 *
 * chunk 0 means no pacing -- read to EOF as fast as the peer sends, which is
 * what every rule without a recv_slow directive does.
 */
typedef struct {
    size_t  chunk;
    long    ms;
    int     rcvbuf;
} http_recv;

int http_request(const char *host, int port,
                 const unsigned char *req, size_t req_len,
                 int timeout_ms, const char *source,
                 const http_pause *pauses, size_t n_pauses,
                 int shut_how, size_t abort_at,
                 const http_recv *recv_opt,
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
