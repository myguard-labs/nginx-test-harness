/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fakesrv.c -- the fake upstream daemon: main(), the poll() loop, syscalls.
 *
 * Everything that decides WHAT to say lives in backend.c and is a pure function
 * over bytes; this file decides WHEN to say it and puts it on a socket. The
 * split is what lets backend_test.c prove the codecs and the script parser
 * without a port, and it keeps the sharp end -- fault timing, resets,
 * half-written replies -- in one reviewable file.
 *
 * Usage:
 *   fakesrv -script PATH [-listen HOST:PORT] [-portfile PATH]
 *           [-journal PATH] [-errfile PATH] [-idle-ms N]
 *
 *
 * FOUR HARD RULES, each of which has a recorded failure behind it:
 *
 * 1. NOTHING is ever written to stdout. The journal goes to a file, errors go
 *    to -errfile. This daemon is started by a shell script that is itself
 *    emitting TAP on stdout, and a single stray line interleaved into that
 *    stream corrupts the test report of a run that otherwise passed.
 *
 * 2. SINGLE PROCESS, poll(), no fork per connection. A forked child inherits
 *    the journal's stdio buffer and flushes a duplicate copy of every buffered
 *    record on exit, so the journal grows records nobody wrote. It also makes
 *    the accept count -- the one observable that proves keepalive reuse -- into
 *    a number that depends on process scheduling.
 *
 * 3. SIGPIPE is ignored and EPIPE is a normal close. This daemon deliberately
 *    writes to sockets it is about to reset and to peers that have already
 *    gone; with the default disposition the FIRST such write kills it with
 *    status 141, and the scenario reports a harness crash where the module was
 *    behaving exactly as the script asked.
 *
 * 4. The portfile is written atomically (tmp + fsync + rename) BEFORE the
 *    listener starts accepting. A shell polling for the port otherwise reads a
 *    zero-length file and parses "" as a port number, roughly one run in
 *    twenty -- the kind of flake that gets a CI leg disabled rather than fixed.
 */

#define _GNU_SOURCE

#include "backend.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>


#define MAX_CONNS   64
#define READ_CHUNK  4096

/* Default idle threshold for an `on=idle` fault, overridable with -idle-ms. */
#define DEFAULT_IDLE_MS  50


typedef struct {
    int             fd;
    int             in_use;

    unsigned char  *in;          /* unconsumed bytes read from the peer */
    size_t          in_len;
    size_t          in_cap;

    unsigned char  *out;         /* reply bytes not yet written */
    size_t          out_len;
    size_t          out_off;

    long            id;          /* journal connection id */
    long            cmds;        /* commands seen on this connection */

    /* Deferred actions, armed by a fault and serviced by the loop. */
    long            close_at_ms; /* close_after: absolute deadline, or -1 */
    long            drip_bytes;  /* drip: piece size, or 0 for "write it all" */
    long            drip_ms;
    long            drip_next_ms;/* absolute time the next piece may go */
    int             close_after_write;
    int             rst_after_write;

    long            last_active_ms;
} conn;


static FILE           *journal;
static FILE           *errout;
static backend_script  script;

static long  conn_seq;
static long  accepts_total;
static long  cmds_total;
static long  conns_max;
static long  conns_now;

/* Per-command occurrence counters, so `on=get:3` means the third get this
 * daemon has seen across every connection -- which is what a scenario can
 * predict, unlike a per-connection count. */
typedef struct {
    char  name[32];
    long  count;
} cmd_counter;

static cmd_counter counters[64];
static size_t      n_counters;

static volatile sig_atomic_t stop_flag;


static void
on_signal(int sig)
{
    (void) sig;
    stop_flag = 1;
}


static long
now_ms(void)
{
    struct timespec ts;

    /*
     * CLOCK_MONOTONIC, not the wall clock: one of the scenarios this daemon
     * exists to serve drives libfaketime, and a fault deadline measured on a
     * clock the test is deliberately moving would fire at a time nobody asked
     * for.
     */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return (long) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}


static void
jlog(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

static void
jlog(const char *fmt, ...)
{
    va_list ap;

    if (journal == NULL) {
        return;
    }

    va_start(ap, fmt);
    vfprintf(journal, fmt, ap);
    va_end(ap);

    fputc('\n', journal);

    /*
     * Flushed per record rather than relying on line buffering. A daemon killed
     * by its scenario's teardown -- which is the normal way this process ends --
     * would otherwise lose the tail of the journal, and the missing records
     * would be exactly the ones describing whatever went wrong last.
     */
    fflush(journal);
}


/* JSON string escaping for journal fields. Values come from a client's wire
 * bytes, so a quote or a control character in a key must not be able to break
 * out of the record and forge a field. */
static void
jstr(FILE *fp, const char *s)
{
    fputc('"', fp);

    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char) *s;

        switch (c) {
        case '"':  fputs("\\\"", fp); break;
        case '\\': fputs("\\\\", fp); break;
        case '\n': fputs("\\n", fp);  break;
        case '\r': fputs("\\r", fp);  break;
        case '\t': fputs("\\t", fp);  break;
        default:
            if (c < 0x20 || c == 0x7f) {
                fprintf(fp, "\\u%04x", c);
            } else {
                fputc((int) c, fp);
            }
        }
    }

    fputc('"', fp);
}


static long
bump_counter(const char *name)
{
    size_t i;

    for (i = 0; i < n_counters; i++) {
        if (strcmp(counters[i].name, name) == 0) {
            return ++counters[i].count;
        }
    }

    if (n_counters >= sizeof(counters) / sizeof(counters[0])) {
        /* Not fatal: a script with more distinct verbs than this table holds
         * still works, it just cannot target the overflow verbs by occurrence.
         * Reported so the omission is visible rather than silent. */
        if (errout != NULL) {
            fprintf(errout, "fakesrv: counter table full, \"%s\" untracked\n",
                    name);
            fflush(errout);
        }
        return -1;
    }

    snprintf(counters[n_counters].name, sizeof(counters[n_counters].name),
             "%s", name);
    counters[n_counters].count = 1;
    n_counters++;

    return 1;
}


static void
conn_close(conn *c, const char *by)
{
    if (!c->in_use) {
        return;
    }

    jlog("{\"ev\":\"close\",\"conn\":%ld,\"by\":\"%s\",\"cmds\":%ld}",
         c->id, by, c->cmds);

    close(c->fd);

    free(c->in);
    free(c->out);

    memset(c, 0, sizeof(*c));
    conns_now--;
}


/* Reset rather than close: SO_LINGER{1,0} makes close() send RST, so the peer
 * sees ECONNRESET instead of a clean FIN. Same primitive as the rule DSL's
 * `abort`, for the same reason -- a module's error path for a reset upstream is
 * not the path it takes for an orderly close. */
static void
conn_reset(conn *c)
{
    struct linger lg;

    lg.l_onoff = 1;
    lg.l_linger = 0;

    (void) setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

    conn_close(c, "reset");
}


static void
out_set(conn *c, unsigned char *buf, size_t len)
{
    free(c->out);

    c->out = buf;
    c->out_len = len;
    c->out_off = 0;
}


/*
 * Apply the fault (if any) for this command to the correct reply, arming
 * whatever deferred behaviour it asks for. Returns 0 when the connection has
 * been destroyed and the caller must stop touching it.
 */
static int
apply_fault(conn *c, const backend_fault *f, unsigned char *reply,
            size_t reply_len)
{
    if (f == NULL) {
        out_set(c, reply, reply_len);
        return 1;
    }

    switch (f->action) {
    case BACKEND_ACT_RST:
        free(reply);
        conn_reset(c);
        return 0;

    case BACKEND_ACT_ACCEPT_CLOSE:
        free(reply);
        conn_close(c, "fault");
        return 0;

    case BACKEND_ACT_TRUNCATE:
        /*
         * Send the first `after` bytes of the reply and then cut. Clamped
         * rather than rejected when the reply is shorter than the cut point:
         * the script is asking for "the reply, severed here", and a get whose
         * value happens to be short should still exercise the sever.
         */
        if ((size_t) f->after < reply_len) {
            reply_len = (size_t) f->after;
        }

        out_set(c, reply, reply_len);
        c->rst_after_write = 1;
        return 1;

    case BACKEND_ACT_LIE_BYTES: {
        size_t         lied_len;
        unsigned char *lied = backend_apply_lie(script.proto, reply, reply_len,
                                                f->delta, &lied_len);

        if (lied == NULL) {
            /* The reply carried no declared length to falsify (an END, a +OK).
             * Send it untouched rather than dropping it: a silently swallowed
             * reply would hang the client on a read that never completes, and
             * the scenario would fail on a timeout instead of on the mismatch
             * it was written to find. */
            out_set(c, reply, reply_len);
            return 1;
        }

        free(reply);
        out_set(c, lied, lied_len);
        return 1;
    }

    case BACKEND_ACT_DRIP:
        out_set(c, reply, reply_len);
        c->drip_bytes = f->bytes;
        c->drip_ms = f->ms;
        c->drip_next_ms = now_ms();
        return 1;

    case BACKEND_ACT_RAW:
        free(reply);
        {
            unsigned char *copy = malloc(f->raw_len ? f->raw_len : 1);

            if (copy == NULL) {
                die("out of memory");
            }

            memcpy(copy, f->raw, f->raw_len);
            out_set(c, copy, f->raw_len);
        }
        return 1;

    case BACKEND_ACT_CLOSE_AFTER:
        out_set(c, reply, reply_len);
        c->close_at_ms = now_ms() + f->ms;
        return 1;

    case BACKEND_ACT_CURSOR_NEVER_ZERO: {
        /*
         * Rewrite the SCAN cursor so it never returns to 0. The client loops
         * "until cursor 0", so this is the shape that hangs it -- a bug class a
         * real redis will never hand you, which is why it needs a fault.
         */
        unsigned char *buf = NULL;
        size_t         len = 0;
        const char    *frame = "*2\r\n$1\r\n7\r\n*0\r\n";

        free(reply);

        len = strlen(frame);
        buf = malloc(len);

        if (buf == NULL) {
            die("out of memory");
        }

        memcpy(buf, frame, len);
        out_set(c, buf, len);
        return 1;
    }

    default:
        out_set(c, reply, reply_len);
        return 1;
    }
}


/*
 * Consume as many complete commands as the read buffer holds. Returns 0 when
 * the connection has been destroyed.
 */
static int
drain_commands(conn *c)
{
    while (c->in_len > 0 && c->out_len == 0) {
        backend_cmd    cmd;
        long           used;
        unsigned char *reply = NULL;
        size_t         reply_len = 0;
        long           nth;
        const backend_fault *f;

        if (script.proto == BACKEND_PROTO_MEMCACHED) {
            used = backend_parse_memcached(c->in, c->in_len, &cmd);
        } else {
            used = backend_parse_resp(c->in, c->in_len, &cmd);
        }

        if (used == 0) {
            /* Incomplete: wait for more bytes. Distinct from the error below,
             * which is why backend_parse_* separates the two returns. */
            return 1;
        }

        if (used < 0) {
            if (errout != NULL) {
                fprintf(errout, "fakesrv: protocol error on conn %ld\n", c->id);
                fflush(errout);
            }

            conn_close(c, "protocol-error");
            return 0;
        }

        c->cmds++;
        cmds_total++;

        nth = bump_counter(cmd.name);

        {
            size_t i;

            fprintf(journal ? journal : stderr,
                    "{\"ev\":\"cmd\",\"conn\":%ld,\"n\":%ld,\"cmd\":",
                    c->id, c->cmds);
            jstr(journal ? journal : stderr, cmd.name);
            fputs(",\"args\":[", journal ? journal : stderr);

            for (i = 0; i < cmd.n_args; i++) {
                if (i > 0) {
                    fputc(',', journal ? journal : stderr);
                }
                jstr(journal ? journal : stderr, cmd.args[i]);
            }

            fputs("]}\n", journal ? journal : stderr);

            if (journal != NULL) {
                fflush(journal);
            }
        }

        if (script.proto == BACKEND_PROTO_MEMCACHED) {
            backend_reply_memcached(&script, &cmd, &reply, &reply_len);
        } else {
            backend_reply_resp(&script, &cmd, &reply, &reply_len);
        }

        /* Consume the bytes BEFORE any fault can destroy the connection --
         * after conn_close() the buffer is freed and this arithmetic would run
         * on a dangling pointer. */
        memmove(c->in, c->in + used, c->in_len - (size_t) used);
        c->in_len -= (size_t) used;

        f = backend_fault_for(&script, cmd.name, nth);

        if (!apply_fault(c, f, reply, reply_len)) {
            return 0;
        }

        /* memcached `quit` produces no reply and ends the connection. */
        if (strcmp(cmd.name, "quit") == 0 && c->out_len == 0) {
            conn_close(c, "quit");
            return 0;
        }
    }

    return 1;
}


static void
write_portfile(const char *path, int port)
{
    char  tmp[4096];
    FILE *fp;
    int   fd;

    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int) sizeof(tmp)) {
        die("portfile path too long: %s", path);
    }

    fp = fopen(tmp, "w");
    if (fp == NULL) {
        die("cannot write portfile %s: %s", tmp, strerror(errno));
    }

    fprintf(fp, "%d\n", port);
    fflush(fp);

    /*
     * fsync before rename. Without it the rename can be visible while the
     * contents are not yet on disk, and the polling shell reads an empty file
     * -- the zero-length-read flake this sequence exists to prevent.
     */
    fd = fileno(fp);
    if (fd >= 0) {
        (void) fsync(fd);
    }

    fclose(fp);

    if (rename(tmp, path) != 0) {
        die("cannot rename portfile into place: %s", strerror(errno));
    }
}


static void
usage(void)
{
    die("usage: fakesrv -script PATH [-listen HOST:PORT] [-portfile PATH] "
        "[-journal PATH] [-errfile PATH] [-idle-ms N]");
}


int
main(int argc, char **argv)
{
    const char        *opt_script = NULL;
    const char        *opt_listen = "127.0.0.1:0";
    const char        *opt_portfile = NULL;
    const char        *opt_journal = NULL;
    const char        *opt_errfile = NULL;
    long               opt_idle_ms = DEFAULT_IDLE_MS;

    int                lfd, i;
    struct sockaddr_in addr;
    socklen_t          alen;
    conn               conns[MAX_CONNS];
    char               host[64];
    int                port = 0;
    struct sigaction   sa;

    memset(conns, 0, sizeof(conns));

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-script") == 0 && i + 1 < argc) {
            opt_script = argv[++i];

        } else if (strcmp(argv[i], "-listen") == 0 && i + 1 < argc) {
            opt_listen = argv[++i];

        } else if (strcmp(argv[i], "-portfile") == 0 && i + 1 < argc) {
            opt_portfile = argv[++i];

        } else if (strcmp(argv[i], "-journal") == 0 && i + 1 < argc) {
            opt_journal = argv[++i];

        } else if (strcmp(argv[i], "-errfile") == 0 && i + 1 < argc) {
            opt_errfile = argv[++i];

        } else if (strcmp(argv[i], "-idle-ms") == 0 && i + 1 < argc) {
            opt_idle_ms = xstrtol(argv[++i], "-idle-ms");

        } else {
            usage();
        }
    }

    if (opt_script == NULL) {
        usage();
    }

    /*
     * Rule 3. Installed before the first socket exists, so there is no window
     * in which a write can take the default disposition.
     */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    /* TERM/INT set a flag rather than exiting, so the summary record is still
     * written -- teardown kills this process, and a journal missing its summary
     * is a journal the scenario cannot assert on. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    if (opt_errfile != NULL) {
        errout = fopen(opt_errfile, "w");
        if (errout == NULL) {
            die("cannot open errfile %s: %s", opt_errfile, strerror(errno));
        }
    } else {
        errout = stderr;
    }

    backend_load(opt_script, &script);

    if (opt_journal != NULL) {
        journal = fopen(opt_journal, "w");
        if (journal == NULL) {
            die("cannot open journal %s: %s", opt_journal, strerror(errno));
        }
        setvbuf(journal, NULL, _IOLBF, 0);
    }

    /* Parse HOST:PORT. */
    {
        const char *colon = strrchr(opt_listen, ':');

        if (colon == NULL || (size_t) (colon - opt_listen) >= sizeof(host)) {
            die("bad -listen \"%s\", want HOST:PORT", opt_listen);
        }

        memcpy(host, opt_listen, (size_t) (colon - opt_listen));
        host[colon - opt_listen] = '\0';
        port = (int) xstrtol(colon + 1, "-listen port");
    }

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        die("socket: %s", strerror(errno));
    }

    {
        int one = 1;
        (void) setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short) port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        die("bad -listen host \"%s\"", host);
    }

    if (bind(lfd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        die("bind %s: %s", opt_listen, strerror(errno));
    }

    if (listen(lfd, 16) != 0) {
        die("listen: %s", strerror(errno));
    }

    /* Read back the bound port, which is the whole point of -listen :0. */
    alen = sizeof(addr);
    if (getsockname(lfd, (struct sockaddr *) &addr, &alen) != 0) {
        die("getsockname: %s", strerror(errno));
    }

    port = ntohs(addr.sin_port);

    /* Rule 4: the portfile lands before the first accept(), so a shell that
     * sees the file can always connect. */
    if (opt_portfile != NULL) {
        write_portfile(opt_portfile, port);
    }

    jlog("{\"ev\":\"listen\",\"port\":%d}", port);

    while (!stop_flag) {
        struct pollfd  pfd[MAX_CONNS + 1];
        int            nfd = 0, idx[MAX_CONNS + 1];
        int            timeout = 100;
        long           t = now_ms();

        pfd[nfd].fd = lfd;
        pfd[nfd].events = POLLIN;
        idx[nfd] = -1;
        nfd++;

        for (i = 0; i < MAX_CONNS; i++) {
            conn *c = &conns[i];

            if (!c->in_use) {
                continue;
            }

            pfd[nfd].fd = c->fd;
            pfd[nfd].events = 0;

            /* Only ask for writability when there is something to write AND,
             * for a dripping reply, the next piece is actually due -- otherwise
             * poll() returns immediately every iteration and the drip becomes a
             * busy loop that writes the whole reply at once. */
            if (c->out_len > c->out_off) {
                if (c->drip_bytes == 0 || t >= c->drip_next_ms) {
                    pfd[nfd].events |= POLLOUT;
                } else {
                    long wait = c->drip_next_ms - t;

                    if (wait < timeout) {
                        timeout = (int) wait;
                    }
                }
            } else {
                pfd[nfd].events |= POLLIN;
            }

            idx[nfd] = i;
            nfd++;
        }

        if (poll(pfd, (nfds_t) nfd, timeout) < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("poll: %s", strerror(errno));
        }

        t = now_ms();

        /* New connections. */
        if (pfd[0].revents & POLLIN) {
            int cfd = accept(lfd, NULL, NULL);

            if (cfd >= 0) {
                int slot = -1;

                for (i = 0; i < MAX_CONNS; i++) {
                    if (!conns[i].in_use) {
                        slot = i;
                        break;
                    }
                }

                if (slot < 0) {
                    close(cfd);

                } else {
                    conn *c = &conns[slot];
                    const backend_fault *f;
                    long nth;

                    memset(c, 0, sizeof(*c));
                    c->fd = cfd;
                    c->in_use = 1;
                    c->id = ++conn_seq;
                    c->close_at_ms = -1;
                    c->last_active_ms = t;

                    accepts_total++;
                    conns_now++;

                    if (conns_now > conns_max) {
                        conns_max = conns_now;
                    }

                    {
                        int one = 1;
                        (void) setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY,
                                          &one, sizeof(one));
                    }

                    jlog("{\"ev\":\"accept\",\"conn\":%ld,\"t_ms\":%ld}",
                         c->id, t);

                    nth = bump_counter("connect");
                    f = backend_fault_for(&script, "connect", nth);

                    if (f != NULL && f->action == BACKEND_ACT_ACCEPT_CLOSE) {
                        conn_close(c, "fault");

                    } else if (f != NULL && f->action == BACKEND_ACT_RST) {
                        conn_reset(c);
                    }
                }
            }
        }

        /* Established connections. */
        for (i = 1; i < nfd; i++) {
            conn *c = &conns[idx[i]];

            if (!c->in_use) {
                continue;
            }

            if (pfd[i].revents & POLLIN) {
                ssize_t n;

                if (c->in_len + READ_CHUNK > c->in_cap) {
                    size_t         want = c->in_cap ? c->in_cap * 2 : READ_CHUNK * 2;
                    unsigned char *bigger;

                    while (want < c->in_len + READ_CHUNK) {
                        want *= 2;
                    }

                    bigger = realloc(c->in, want);
                    if (bigger == NULL) {
                        die("out of memory");
                    }

                    c->in = bigger;
                    c->in_cap = want;
                }

                n = read(c->fd, c->in + c->in_len, READ_CHUNK);

                if (n > 0) {
                    c->in_len += (size_t) n;
                    c->last_active_ms = t;

                    if (!drain_commands(c)) {
                        continue;
                    }

                } else if (n == 0) {
                    conn_close(c, "peer");
                    continue;

                } else if (errno != EAGAIN && errno != EWOULDBLOCK
                           && errno != EINTR)
                {
                    conn_close(c, "read-error");
                    continue;
                }
            }

            if ((pfd[i].revents & POLLOUT) && c->out_len > c->out_off) {
                size_t  want = c->out_len - c->out_off;
                ssize_t n;

                if (c->drip_bytes > 0 && (size_t) c->drip_bytes < want) {
                    want = (size_t) c->drip_bytes;
                }

                n = write(c->fd, c->out + c->out_off, want);

                if (n > 0) {
                    c->out_off += (size_t) n;
                    c->last_active_ms = t;

                    if (c->drip_bytes > 0) {
                        c->drip_next_ms = t + c->drip_ms;
                    }

                    if (c->out_off >= c->out_len) {
                        /* Reply fully written. */
                        free(c->out);
                        c->out = NULL;
                        c->out_len = 0;
                        c->out_off = 0;
                        c->drip_bytes = 0;

                        if (c->rst_after_write) {
                            conn_reset(c);
                            continue;
                        }

                        if (c->close_after_write) {
                            conn_close(c, "fault");
                            continue;
                        }

                        /* More pipelined commands may be waiting. */
                        if (!drain_commands(c)) {
                            continue;
                        }
                    }

                } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK
                           && errno != EINTR)
                {
                    /* Rule 3: EPIPE is a normal close here, not an error. */
                    conn_close(c, errno == EPIPE ? "peer" : "write-error");
                    continue;
                }
            }

            if (pfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                conn_close(c, "peer");
                continue;
            }
        }

        /* Deferred closes: close_after deadlines and idle faults. */
        for (i = 0; i < MAX_CONNS; i++) {
            conn *c = &conns[i];

            if (!c->in_use) {
                continue;
            }

            if (c->close_at_ms >= 0 && t >= c->close_at_ms) {
                conn_close(c, "close_after");
                continue;
            }

            if (c->out_len == 0 && t - c->last_active_ms >= opt_idle_ms) {
                const backend_fault *f = backend_fault_for(&script, "idle",
                                                           BACKEND_NTH_ANY);

                if (f != NULL && f->action == BACKEND_ACT_CLOSE_AFTER
                    && t - c->last_active_ms >= f->ms)
                {
                    /* The keepalive-pool case: the peer parked this connection
                     * and the backend hangs up underneath it. */
                    conn_close(c, "idle");
                    continue;
                }
            }
        }
    }

    for (i = 0; i < MAX_CONNS; i++) {
        conn_close(&conns[i], "shutdown");
    }

    close(lfd);

    /*
     * The summary. This single record is what makes the keepalive claim
     * falsifiable in one line: accepts==1 with cmds==5 proves the connection
     * was reused, accepts==5 proves it was not, and no amount of reading the
     * module's own logs settles it as directly.
     */
    jlog("{\"ev\":\"summary\",\"accepts\":%ld,\"conns_max\":%ld,\"cmds\":%ld}",
         accepts_total, conns_max, cmds_total);

    if (journal != NULL) {
        fclose(journal);
    }

    if (errout != NULL && errout != stderr) {
        fclose(errout);
    }

    backend_free(&script);

    return 0;
}
