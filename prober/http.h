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

    /* How the read loop ended, and how long after the request went out.
     *
     * `close_ms` is measured from the moment the last request byte is written
     * to the moment the loop stops, so it is the server's latency to act, not
     * this process's wall clock. Meaningful only when close_reason is
     * HTTP_CLOSE_FIN or HTTP_CLOSE_TIMEOUT.
     *
     * The reason is what keeps two very different events from reading alike. A
     * server that closes and a server that never closes both leave this process
     * with whatever bytes arrived; only the reason distinguishes "the peer said
     * it was done" from "we stopped waiting". An assertion that cannot tell
     * them apart would pass on a server that holds a connection open forever,
     * which is precisely the defect the close-deadline directive exists to
     * catch.
     *
     * `long` is deliberate here even though the clock behind it is 64-bit:
     * this is a DIFFERENCE of two timestamps, bounded by the read timeout, so
     * it cannot overflow 32 bits the way an absolute monotonic-milliseconds
     * value does after ~24 days of uptime. The absolute values are computed and
     * subtracted in long long inside http.c; only the small result lands here.
     */
    int     close_reason;
    long    close_ms;

    /*
     * Chunked body decoded by http_dechunk(), or NULL if the case never asked.
     *
     * OWNED storage, unlike `body`, which borrows into `raw`. The decode cannot
     * be done in place: it is only ever shorter than the raw body, but writing
     * the result over `raw` would destroy the wire bytes, and the wire bytes are
     * what a harness built to provoke invalid chunked framing exists to inspect.
     * A rule that asks for `dechunk` gets the decoded octets; `raw` and `body`
     * keep meaning exactly what they meant before, so no pre-existing rule
     * changes behaviour by construction.
     *
     * Meaningful only when `dechunk_status` is HTTP_DECHUNK_OK. On any framing
     * error this stays NULL and the status carries the reason -- a partially
     * decoded buffer offered as "the body" would let an assertion pass on the
     * prefix of a response whose framing the server got wrong, which is the
     * false PASS this decoder exists to prevent.
     */
    char   *decoded;
    size_t  decoded_len;
    int     dechunk_status;
} http_response;

/*
 * Result of decoding a chunked body.
 *
 * Every framing defect gets its OWN code rather than collapsing into one
 * "malformed" value. The harness's job here is to say which rule the server
 * broke, and a single failure code would report a missing terminator and a
 * corrupt length as the same event -- the two have very different causes, and
 * a response-smuggling test that cannot tell them apart is not testing much.
 *
 * NOT_CHUNKED is not an error: it is what a plain identity body reports, so a
 * caller can distinguish "no chunked framing here" from "chunked framing that
 * is wrong". NO_LAST_CHUNK is the `[no-last-chunk]` case from the roadmap --
 * every chunk parsed cleanly but the terminating 0-chunk never arrived, which
 * is exactly how a truncated-but-plausible response looks on the wire.
 */
#define HTTP_DECHUNK_NONE          0  /* http_dechunk() was never called   */
#define HTTP_DECHUNK_OK            1
#define HTTP_DECHUNK_NOT_CHUNKED   2  /* no Transfer-Encoding: chunked     */
#define HTTP_DECHUNK_BAD_SIZE      3  /* non-hex, empty, or overflowing    */
#define HTTP_DECHUNK_BAD_CRLF      4  /* chunk data not followed by CRLF   */
#define HTTP_DECHUNK_TRUNCATED     5  /* chunk shorter than its size line  */
#define HTTP_DECHUNK_NO_LAST_CHUNK 6  /* clean chunks, no terminating 0    */

/*
 * Decode `resp`'s chunked body into resp->decoded, setting resp->dechunk_status.
 *
 * Safe to call on any response, including one with no body, no headers, or a
 * body that is not chunked at all -- those report NOT_CHUNKED rather than
 * failing. Calling it twice is safe and recomputes from `raw`.
 */
void http_dechunk(http_response *resp);

/*
 * Human-readable reason for a dechunk status, for TAP diagnostics.
 *
 * Never returns NULL: an unrecognised code renders literally, so a status added
 * to the enum without a string here shows up as an obviously wrong diagnostic
 * rather than crashing the printf that consumes it.
 */
const char *http_dechunk_reason(int status);

/*
 * Why the read loop stopped.
 *
 * NONE covers the paths that never read at all (abort, hold): no close was
 * observed by this process, so a close-deadline assertion has nothing to judge
 * and must say so rather than treat "not measured" as "did not close".
 *
 * TIMEOUT is deliberately a normal outcome carried on a SUCCESSFUL return
 * rather than the transport error it used to be, but only when the caller opts
 * in via `want_close`. "The server did not close within the deadline" is the
 * exact failure a close assertion exists to report, and reporting it as a
 * harness error would print "request failed" and skip every assertion in the
 * case -- including the one that was asking the question.
 */
#define HTTP_CLOSE_NONE     0
#define HTTP_CLOSE_FIN      1   /* peer sent FIN; read() returned 0    */
#define HTTP_CLOSE_RESET    2   /* peer reset; read() failed ECONNRESET */
#define HTTP_CLOSE_TIMEOUT  3   /* deadline passed, peer still open    */

/*
 * Outcomes that only an idle wait (`want_idle`) can produce.
 *
 * IDLE is its PASS: the wait ran to completion with the peer silent and the
 * connection up. DATA is its failure-by-action: the peer sent something before
 * the wait expired. A close during the wait is not given a reason of its own --
 * it reports FIN or RESET above, so the assertion layer can name the manner of
 * the close with the same words it uses for a missed close deadline.
 */
#define HTTP_CLOSE_IDLE     4   /* idle wait expired, peer silent and open */
#define HTTP_CLOSE_DATA     5   /* peer sent data before the wait expired  */


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
 * `hold_ms` writes the whole request, waits that many milliseconds without
 * reading a byte, then closes normally.
 *
 * This is the third way a client can walk away, and it is deliberately the
 * polite one. `abort` resets, so the server's read fails and no response can be
 * written. `shutdown(SHUT_WR)` half-closes, and the response still arrives. This
 * does neither: the connection stays fully open and idle while the server writes
 * a response that nobody will ever read, and only then does it end with an
 * ordinary FIN.
 *
 * What that exercises is the server's grip on a completed request whose client
 * has gone quiet -- a response sitting in the send buffer, the connection still
 * established, nothing wrong at the TCP level for the event loop to react to.
 * A server that keys cleanup off an error or an EOF sees neither here. The
 * failure it catches is a connection or buffer held until a timeout expires
 * rather than released when the response was handed off.
 *
 * Like `abort`, this SKIPS the read loop and returns success with status -1 and
 * an empty body, so a case must judge the server from its log or the probe
 * counters. Unlike `abort`, the response really was written -- this process just
 * never collects it. Zero means no hold, which is what every rule without a
 * `hold` directive does.
 */
#define HTTP_HOLD_NONE  0

/* The transport's own off value for the idle wait, kept here beside
 * HTTP_ABORT_NONE and HTTP_HOLD_NONE rather than reusing rules.h's
 * IDLE_NONE: http.c knows nothing about rule files, and a transport that
 * had to include the parser's header to run a socket would invert the layering.
 * The two constants share a value, and rules_test asserts they still do. */
#define HTTP_IDLE_NONE  (-1)

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

/*
 * AUD-07: two ceilings on response collection, because SO_RCVTIMEO is a
 * PER-READ idle timeout, not a whole-exchange one. A server that trickles a
 * byte just inside each read's window never trips it: the read loop keeps
 * succeeding, keeps doubling its buffer, and never reaches the deadline the
 * caller intended -- so a targeted PR case degrades into a hung runner or an
 * OOM. Both matter here precisely because the harness deliberately sends
 * malformed input to buggy servers.
 *
 * HTTP_MAX_RESPONSE bounds memory: 8 MiB is orders of magnitude above any probe
 * JSON or test fixture this harness reads, so a response over it is a runaway,
 * not a legitimate payload.
 *
 * HTTP_MAX_EXCHANGE_MS bounds wall time end-to-end, derived per call as 8x the
 * per-read timeout. A well-behaved exchange finishes in roughly one read
 * window; a paced recv_slow case (a few bounded chunks) finishes in a small
 * multiple of it; only an endless trickle -- a byte per read window, forever --
 * runs long enough to be cut off. Tying it to the per-read timeout keeps it
 * proportional: a case that deliberately raises -t to accommodate a slow server
 * gets a proportionally larger whole-exchange budget for free. Exceeding either
 * ceiling is a harness-side failure of that one case, reported as such -- never
 * a silent pass.
 */
#define HTTP_MAX_RESPONSE      (8 * 1024 * 1024)
#define HTTP_MAX_EXCHANGE_MS(per_read)  ((long) ((per_read) * 8L))

/*
 * `want_close` makes a read timeout a RESULT instead of an error.
 *
 * By default a server that never closes exhausts timeout_ms and this call
 * fails: the response is incomplete, nothing can be asserted about it, and the
 * caller is told the request did not work. That is right for every case that
 * wants a response and did not get one.
 *
 * It is exactly wrong for a case asserting the server closes within a
 * deadline. There, "it never closed" is the finding -- the one the rule was
 * written to detect -- and turning it into a transport failure would abandon
 * the case before the assertion that asks about it ever runs, reporting a
 * harness error for a real server defect. With this set, the timeout instead
 * returns success with close_reason HTTP_CLOSE_TIMEOUT and whatever bytes did
 * arrive, and the verdict is left to the assertion layer where it belongs.
 *
 * Pass 0 for the historical behaviour, which is what every case without a
 * close-deadline assertion does.
 *
 * `idle_ms` replaces the read loop with an idle wait: poll the socket for
 * that many milliseconds and report what the peer did, WITHOUT reading. The
 * response is deliberately not collected -- the assertion is that nothing
 * arrived, so consuming bytes would destroy the evidence and reading would
 * consume the readiness itself. Outcomes land in close_reason as HTTP_CLOSE_IDLE
 * (silent for the whole wait -- the pass), HTTP_CLOSE_DATA (the peer sent
 * something), or FIN/RESET (the peer closed), with close_ms measured from the
 * last request byte in every case.
 *
 * Pass IDLE_NONE (-1) to run the ordinary read loop, which is what every
 * case without an idle-wait assertion does. Mutually exclusive with hold_ms and
 * abort_at at the parser level, since neither of those observes the socket.
 */
int http_request(const char *host, int port,
                 const unsigned char *req, size_t req_len,
                 int timeout_ms, const char *source,
                 const http_pause *pauses, size_t n_pauses,
                 int shut_how, size_t abort_at, long hold_ms,
                 const http_recv *recv_opt, int want_close,
                 long idle_ms,
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
