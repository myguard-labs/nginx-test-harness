/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * http.c -- see http.h.
 */

/* _GNU_SOURCE for memmem(): the response body is binary, so the header
 * terminator must be located by length-bounded search, never by strstr(). */
#define _GNU_SOURCE

#include "http.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


void
http_response_free(http_response *resp)
{
    if (resp == NULL) {
        return;
    }

    free(resp->raw);
    free(resp->headers);

    resp->raw = NULL;
    resp->headers = NULL;
    resp->body = NULL;
    resp->raw_len = 0;
    resp->body_len = 0;
}


/*
 * send(MSG_NOSIGNAL) rather than write(): several rule files deliberately
 * provoke the server into closing mid-request (malformed framing, oversized
 * headers), and a plain write() to a closed peer raises SIGPIPE, whose default
 * action would kill the whole prober. A harness that dies on the case it was
 * written to exercise reports a crash as a missing test, so the failure has to
 * arrive as EPIPE on this one request instead.
 */
static int
write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (n == 0) {
            return -1;
        }

        off += (size_t) n;
    }

    return 0;
}


void
http_parse_response(http_response *resp)
{
    char   *sep;
    size_t  header_len;

    resp->status = -1;
    resp->body = NULL;
    resp->body_len = 0;
    resp->headers = NULL;

    if (resp->raw == NULL || resp->raw_len == 0) {
        return;
    }

    /*
     * A status line is "HTTP/<digit>+.<digit>+ <code> <reason>". A bare
     * "HTTP/" prefix check followed by "find the first space anywhere" would
     * accept "HTTP/xyz 200 OK" -- the garbage after the slash never gets
     * looked at, so it parses a real status out of a malformed version line.
     * That is a false PASS for any rule asserting status=200, the worst
     * failure mode for a harness: it reports success on input the server
     * (or an attacker) never sent as valid HTTP. So the version token is
     * walked byte by byte and the terminating space must be the one that
     * ends *that* token, not merely the first space in the buffer.
     *
     * Only HTTP/1.x is accepted. nginx and angie only ever put HTTP/1.0 or
     * HTTP/1.1 on the wire for the framing this prober reads (h2/h3 are
     * negotiated, not spelled out in a text status line), so a bare
     * "HTTP/2" with no minor version is exactly the kind of malformed input
     * this fix exists to reject, not a real case to special-case for.
     */
    if (resp->raw_len > 5 && memcmp(resp->raw, "HTTP/", 5) == 0) {
        size_t  i = 5;
        int     saw_major = 0;
        int     saw_minor = 0;

        while (i < resp->raw_len && resp->raw[i] >= '0' && resp->raw[i] <= '9') {
            i++;
            saw_major = 1;
        }

        if (saw_major && i < resp->raw_len && resp->raw[i] == '.') {
            i++;

            while (i < resp->raw_len
                   && resp->raw[i] >= '0' && resp->raw[i] <= '9')
            {
                i++;
                saw_minor = 1;
            }
        }

        if (saw_major && saw_minor
            && i < resp->raw_len && resp->raw[i] == ' ')
        {
            char *end;
            long  code = strtol(resp->raw + i + 1, &end, 10);

            /* strtol reports "no digits" by leaving end at the start, and
             * returns 0 for it -- indistinguishable from a literal "0" status
             * unless the end pointer is checked. The header promises -1 for
             * anything unparseable, so a non-numeric token must not surface
             * as a status a rule could match on. */
            if (end != resp->raw + i + 1 && code >= 0 && code <= INT_MAX) {
                resp->status = (int) code;
            }
        }
    }

    /*
     * Split on the header terminator. A response with no CRLFCRLF is left with
     * headers == NULL and no body rather than being guessed at -- silently
     * treating a truncated response as "all headers" would make a connection
     * reset look like a successful empty reply.
     */
    sep = memmem(resp->raw, resp->raw_len, "\r\n\r\n", 4);
    if (sep == NULL) {
        return;
    }

    header_len = (size_t) (sep - resp->raw);

    resp->headers = malloc(header_len + 1);
    if (resp->headers != NULL) {
        memcpy(resp->headers, resp->raw, header_len);
        resp->headers[header_len] = '\0';
    }

    resp->body = sep + 4;
    resp->body_len = resp->raw_len - header_len - 4;
}


/*
 * Sleep `ms`, resuming across signals rather than returning early: a pause cut
 * short by a stray signal would silently write the rest of the request sooner
 * than the rule file asked for, turning a timing test into a flaky one.
 */
static void
sleep_ms(long ms)
{
    struct timespec  ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;

    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
        /* ts now holds the remaining time; go again. */
    }
}


/*
 * Write `len` bytes `chunk` at a time, sleeping `ms` between writes. The sleep
 * goes BETWEEN chunks only -- a trailing sleep after the final chunk would
 * delay the response rather than the request, which is a different test.
 */
static int
write_paced(int fd, const unsigned char *buf, size_t len,
            size_t chunk, long ms)
{
    size_t  off = 0;

    while (off < len) {
        size_t  n = len - off;

        if (n > chunk) {
            n = chunk;
        }

        if (write_all(fd, buf + off, n) != 0) {
            return -1;
        }

        off += n;

        if (off < len) {
            sleep_ms(ms);
        }
    }

    return 0;
}


/*
 * Write the request, stalling at each pause offset. With no pauses this is a
 * single write_all() of the whole buffer -- byte-identical to what this
 * function did before pauses existed.
 */
static int
write_request(int fd, const unsigned char *req, size_t req_len,
              const http_pause *pauses, size_t n_pauses)
{
    size_t  off = 0, i;

    for (i = 0; i < n_pauses; i++) {
        size_t  upto = pauses[i].offset;

        if (upto > req_len) {
            upto = req_len;
        }

        if (upto > off) {
            if (write_all(fd, req + off, upto - off) != 0) {
                return -1;
            }
            off = upto;
        }

        if (pauses[i].chunk > 0) {
            /* Paced entry: dribble from here to the next entry's offset (or
             * the end), rather than stalling once. The leading sleep keeps a
             * paced entry's `ms` meaning the same "hold off, then act" as a
             * plain pause, so the two read alike in a rule file. */
            size_t  upto_next = req_len;

            if (i + 1 < n_pauses && pauses[i + 1].offset < upto_next) {
                upto_next = pauses[i + 1].offset;
            }

            if (upto_next < off) {
                upto_next = off;
            }

            sleep_ms(pauses[i].ms);

            if (write_paced(fd, req + off, upto_next - off,
                            pauses[i].chunk, pauses[i].ms) != 0)
            {
                return -1;
            }

            off = upto_next;
            continue;
        }

        sleep_ms(pauses[i].ms);
    }

    if (off < req_len) {
        return write_all(fd, req + off, req_len - off);
    }

    return 0;
}


int
http_request(const char *host, int port,
             const unsigned char *req, size_t req_len,
             int timeout_ms, const char *source,
             const http_pause *pauses, size_t n_pauses,
             int shut_how, size_t abort_at,
             http_response *resp,
             char *errbuf, size_t errlen)
{
    int                 fd, one = 1;
    char               *buf = NULL;
    size_t              cap = 8192, len = 0;
    struct sockaddr_in  sin;
    struct timeval      tv;

    memset(resp, 0, sizeof(*resp));
    resp->status = -1;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t) port);

    if (inet_pton(AF_INET, host, &sin.sin_addr) != 1) {
        snprintf(errbuf, errlen, "bad host address \"%s\"", host);
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(errbuf, errlen, "socket: %s", strerror(errno));
        return -1;
    }

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Nagle would coalesce the deliberately-split writes some rules depend on
     * to exercise request smuggling and partial-header handling. */
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    if (source != NULL) {
        struct sockaddr_in  local;

        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_port = 0;

        if (inet_pton(AF_INET, source, &local.sin_addr) != 1) {
            snprintf(errbuf, errlen, "bad source address \"%s\"", source);
            close(fd);
            return -1;
        }

        /* SO_REUSEADDR so a rule can reuse a source address while an earlier
         * connection from it is still in TIME_WAIT. */
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        if (bind(fd, (struct sockaddr *) &local, sizeof(local)) != 0) {
            snprintf(errbuf, errlen, "bind %s: %s", source, strerror(errno));
            close(fd);
            return -1;
        }
    }

    if (connect(fd, (struct sockaddr *) &sin, sizeof(sin)) != 0) {
        snprintf(errbuf, errlen, "connect %s:%d: %s",
                 host, port, strerror(errno));
        close(fd);
        return -1;
    }

    /*
     * An aborting case writes only the prefix it means to send. Truncating
     * req_len here rather than adding a mode to write_request() keeps the
     * pacing logic untouched: the pauses that fall inside the prefix still
     * apply, so `send_slow` followed by `abort` dribbles and then resets, which
     * is the shape a real slowloris client presents when it gives up.
     */
    if (write_request(fd, req,
                      abort_at < req_len ? abort_at : req_len,
                      pauses, n_pauses) != 0)
    {
        snprintf(errbuf, errlen, "write: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /*
     * SO_LINGER{on, 0} turns the close below into a reset instead of a FIN.
     * The socket is discarded with whatever is still queued, so the server's
     * next read fails with ECONNRESET rather than reporting a clean EOF.
     *
     * There is deliberately no read loop after this: the peer has been told the
     * connection no longer exists, so waiting for a response would only spend
     * timeout_ms proving that nothing arrives. The case is judged from the
     * server's own log and counters, and returning success with an empty
     * response is what lets those assertions run at all.
     *
     * setsockopt's return is checked because a failure here would silently
     * downgrade the reset to an ordinary close -- the connection would end with
     * a FIN, the server would see a well-behaved client, and the case would
     * report a pass for the opposite of the behaviour it asked to test.
     */
    if (abort_at != HTTP_ABORT_NONE) {
        struct linger  lg;

        lg.l_onoff = 1;
        lg.l_linger = 0;

        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)) != 0) {
            snprintf(errbuf, errlen, "SO_LINGER: %s", strerror(errno));
            close(fd);
            return -1;
        }

        close(fd);

        resp->raw = malloc(1);
        if (resp->raw == NULL) {
            snprintf(errbuf, errlen, "out of memory");
            return -1;
        }

        resp->raw[0] = '\0';
        resp->raw_len = 0;

        return 0;
    }

    /*
     * The return value is deliberately ignored. shutdown() fails with ENOTCONN
     * when the peer has already torn the connection down -- which is a normal
     * outcome for the malformed-input cases this directive exists to serve, not
     * a harness fault. Whatever the server did is judged from the response and
     * the log, so failing the case here would report a harness error for the
     * very behaviour under test.
     */
    if (shut_how != HTTP_SHUT_NONE) {
        (void) shutdown(fd, shut_how);
    }

    buf = malloc(cap);
    if (buf == NULL) {
        snprintf(errbuf, errlen, "out of memory");
        close(fd);
        return -1;
    }

    for ( ;; ) {
        ssize_t n;

        if (len + 4096 > cap) {
            char *bigger;

            cap *= 2;
            bigger = realloc(buf, cap);
            if (bigger == NULL) {
                snprintf(errbuf, errlen, "out of memory");
                free(buf);
                close(fd);
                return -1;
            }
            buf = bigger;
        }

        n = read(fd, buf + len, cap - len - 1);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                snprintf(errbuf, errlen,
                         "read timed out after %d ms (%zu bytes so far); "
                         "does the request ask for Connection: close?",
                         timeout_ms, len);
                free(buf);
                close(fd);
                return -1;
            }

            /* A reset after a complete response is a legitimate outcome for
             * malformed-input cases; keep what we have and let the rule judge. */
            break;
        }

        if (n == 0) {
            break;
        }

        len += (size_t) n;
    }

    close(fd);

    buf[len] = '\0';
    resp->raw = buf;
    resp->raw_len = len;

    http_parse_response(resp);

    return 0;
}


/*
 * ASCII-only case fold, deliberately NOT tolower()/strncasecmp().
 *
 * Measured under LC_ALL=tr_TR.UTF-8 (locale-hostility CI leg,
 * http_locale_check.c): glibc's tr_TR LC_CTYPE table makes 'I' and 'i'
 * fixed points of tolower()/toupper() -- tolower('I') == 'I', not 'i' --
 * rather than folding them onto each other the way the C locale does, and
 * glibc's strncasecmp()/strcasecmp() consult that same table. The practical
 * effect on the unmodified code: strncasecmp("ICE-Auth", "ice-auth", 8)
 * compared equal under the C locale and did not under tr_TR, so a header
 * name or value differing from the needle only in 'I'/'i' casing silently
 * stopped matching whenever the calling process' environment set a Turkish
 * locale -- which nothing in this codebase controls, since it is inherited
 * from whatever invoked the prober.
 *
 * HTTP header names are ASCII by construction (RFC 9110 token syntax), so
 * this search has no business consulting ANY locale table at all -- byte
 * comparison with a hand-rolled fold over 'A'-'Z' only is both correct and,
 * unlike strncasecmp(), immune to the invoking process' environment.
 */
static unsigned char
ascii_fold(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (unsigned char) (c - 'A' + 'a');
    }
    return c;
}


static int
ascii_case_eq(const char *a, const char *b, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (ascii_fold((unsigned char) a[i]) != ascii_fold((unsigned char) b[i])) {
            return 0;
        }
    }

    return 1;
}


int
http_has_header(const http_response *resp, const char *needle)
{
    const char *line;
    size_t      nlen;

    if (resp->headers == NULL) {
        return 0;
    }

    nlen = strlen(needle);
    line = resp->headers;

    while (line != NULL && *line != '\0') {
        const char *eol = strstr(line, "\r\n");
        size_t      llen = (eol != NULL) ? (size_t) (eol - line) : strlen(line);

        if (llen >= nlen) {
            size_t i;

            for (i = 0; i + nlen <= llen; i++) {
                if (ascii_case_eq(line + i, needle, nlen)) {
                    return 1;
                }
            }
        }

        line = (eol != NULL) ? eol + 2 : NULL;
    }

    return 0;
}
