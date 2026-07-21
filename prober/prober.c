/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * prober.c -- rule-driven HTTP prober for nginx/angie modules.
 *
 * This file is the driver only: it walks the cases, issues the requests, and
 * prints TAP. The parts that decide anything live beside it, so they can be
 * tested without a server -- rules.c (text -> cases), assert.c (documents ->
 * verdicts), json.c (the oracle), http.c (the wire).
 *
 * Module-agnostic by construction: every case is data in a .rule file, and the
 * only thing this knows about the module under test is the probe endpoint's
 * JSON shape, which ngx_test_probe.c keeps generic.
 *
 * Why this exists alongside the Perl suite in t/ rather than replacing it:
 *
 *   1. It runs against ANGIE. Stock Test::Nginx::Socket probes the server's
 *      version banner and requires "nginx version: x.y" (Util.pm:1365); angie
 *      answers "Angie version: Angie/1.12.0", so the harness bails before the
 *      first test and the angie CI leg has only ever been build-and-load. This
 *      prober reads no banner, so the same rules run on both servers.
 *
 *   2. It asserts on IN-WORKER state, not just the response. A rule can require
 *      that the ban zone gained exactly one node, which no amount of response
 *      matching can establish.
 *
 * See rules.h for the rule-file syntax.
 *
 * `from 127.0.0.9` binds the client socket to a local source address, so a
 * rule can present itself as a distinct peer. Ban behaviour is keyed on the
 * peer, so this is what makes per-address ban logic testable at all.
 *
 * Every request must ask for Connection: close; see http.h for why.
 *
 * Output is TAP, so `prove` consumes it exactly like the Perl suite.
 */

#define _GNU_SOURCE

#include "assert.h"
#include "http.h"
#include "json.h"
#include "rules.h"
#include "util.h"

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


static const char  *opt_host = "127.0.0.1";
static int          opt_port = 18099;
static const char  *opt_probe_uri = "/__probe";
static int          opt_timeout_ms = 5000;
static int          opt_verbose = 0;

/* --check: parse the rule files, report, and exit without sending a request.
 * Deliberately emits no TAP plan -- a run that never executed a case has not
 * asserted anything, and "1..0" reads to a consumer as a suite that passed. */
static int          opt_check = 0;

/* Path to the server's error log, from -e or PROBER_ERROR_LOG (run.sh exports
 * the latter). NULL means the no_error_log / grep_error_log directives cannot
 * be evaluated -- and a case that carries one then FAILS rather than skips. */
static const char  *opt_error_log = NULL;


/*
 * Current size of the error log, taken as the case's start mark.
 *
 * A missing file marks position 0: the server may simply not have logged yet,
 * and the first line it eventually writes belongs to whichever case is running
 * when it appears.
 */
static long
error_log_mark(void)
{
    long   size;
    FILE  *fp = fopen(opt_error_log, "rb");

    if (fp == NULL) {
        return 0;
    }

    if (fseek(fp, 0L, SEEK_END) != 0) {
        size = 0;
    } else {
        size = ftell(fp);

        if (size < 0) {
            size = 0;
        }
    }

    fclose(fp);

    return size;
}


/*
 * Read everything appended since `mark` -- the case's own slice of the log.
 *
 * Sliced by offset rather than re-grepping the whole file so that a line
 * logged by an EARLIER case can neither satisfy this case's grep_error_log
 * nor trip its no_error_log. Returns a malloc'd buffer (caller frees) and its
 * length; an unreadable or unchanged file is an empty slice, which is a valid
 * answer -- "nothing was logged" -- not an error.
 */
static char *
read_log_slice(long mark, size_t *out_len)
{
    char   *buf;
    long    end;
    size_t  len;
    FILE   *fp;

    *out_len = 0;

    fp = fopen(opt_error_log, "rb");
    if (fp == NULL) {
        return NULL;
    }

    if (fseek(fp, 0L, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }

    end = ftell(fp);

    if (end < 0 || end <= mark || fseek(fp, mark, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    len = (size_t) (end - mark);

    buf = malloc(len);
    if (buf == NULL) {
        die("out of memory");
    }

    /* A short read only shrinks the slice (the file cannot shrink while the
     * server appends); assert over what was actually read. */
    *out_len = fread(buf, 1, len, fp);
    fclose(fp);

    return buf;
}


/*
 * Issue a probe request carrying a fault directive, e.g. "fault_slab=1".
 * The reply is discarded: what matters is the side effect on the zone, and the
 * following case's own probe assertions verify it took.
 */
static int
arm_fault(const char *query, const char *source, char *errbuf, size_t errlen)
{
    char           req[512];
    int            n;
    http_response  resp;

    n = snprintf(req, sizeof(req),
                 "GET %s?%s HTTP/1.1\r\nHost: prober\r\n"
                 "Connection: close\r\n\r\n",
                 opt_probe_uri, query);

    /* snprintf reports what it WOULD have written, so on truncation n exceeds
     * the buffer; handing that length to http_request() would read off the end
     * of the stack. A long fault query is a rule-file mistake, so say so. */
    if (n < 0 || (size_t) n >= sizeof(req)) {
        snprintf(errbuf, errlen, "fault query \"%.64s\" does not fit in a "
                 "%zu-byte request buffer", query, sizeof(req));
        return -1;
    }

    if (http_request(opt_host, opt_port, (const unsigned char *) req,
                     (size_t) n, opt_timeout_ms, source, NULL, 0,
                     HTTP_SHUT_NONE, HTTP_ABORT_NONE, HTTP_HOLD_NONE,
                     NULL, 0, HTTP_IDLE_NONE, &resp,
                     errbuf, errlen) != 0)
    {
        return -1;
    }

    if (resp.status != 200) {
        snprintf(errbuf, errlen, "arming \"%.64s\" returned status %d",
                 query, resp.status);
        http_response_free(&resp);
        return -1;
    }

    http_response_free(&resp);
    return 0;
}


static json_value *
fetch_probe(char *errbuf, size_t errlen)
{
    char           req[512];
    int            n;
    const char    *jerr = NULL;
    json_value    *doc;
    http_response  resp;

    n = snprintf(req, sizeof(req),
                 "GET %s HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n",
                 opt_probe_uri);

    if (n < 0 || (size_t) n >= sizeof(req)) {
        snprintf(errbuf, errlen, "probe URI \"%.64s\" does not fit in a "
                 "%zu-byte request buffer", opt_probe_uri, sizeof(req));
        return NULL;
    }

    if (http_request(opt_host, opt_port, (const unsigned char *) req,
                     (size_t) n, opt_timeout_ms, NULL, NULL, 0,
                     HTTP_SHUT_NONE, HTTP_ABORT_NONE, HTTP_HOLD_NONE,
                     NULL, 0, HTTP_IDLE_NONE, &resp,
                     errbuf, errlen) != 0)
    {
        return NULL;
    }

    if (resp.status != 200) {
        snprintf(errbuf, errlen, "probe endpoint returned status %d "
                 "(is the probe directive configured, and was the module built "
                 "with TEST_HARNESS=1?)", resp.status);
        http_response_free(&resp);
        return NULL;
    }

    if (resp.body == NULL) {
        snprintf(errbuf, errlen, "probe response had no body");
        http_response_free(&resp);
        return NULL;
    }

    /* AUD-11: parse the body by its true LENGTH, not by strlen. A probe reply
     * carrying an embedded NUL followed by trailing bytes would otherwise be
     * truncated at the NUL by json_parse, which accepts the valid prefix and
     * never sees the garbage the trailing-bytes check is meant to reject -- so a
     * corrupt or smuggled probe document would read as healthy. */
    doc = json_parse_n(resp.body, resp.body_len, &jerr);

    if (doc == NULL) {
        snprintf(errbuf, errlen, "probe JSON parse failed: %s",
                 jerr ? jerr : "unknown");
    }

    http_response_free(&resp);

    return doc;
}


/*
 * How many times to re-read the probe before believing a delta failure, and
 * how long to wait between reads.
 *
 * The worker closes the case's connection asynchronously, so an fd or
 * connection delta can read as +1 purely because the close has not been
 * processed yet -- a race, not a leak. Re-reading absorbs that. It cannot
 * absorb a real leak: a leaked fd never comes back, so every retry sees the
 * same delta and the case still fails, only later. Bounded so a genuine
 * failure costs a fifth of a second rather than hanging the run.
 */
#define DELTA_SETTLE_TRIES  8
#define DELTA_SETTLE_US     25000


/*
 * Returns 1 if the case passed. Diagnostics are printed as TAP comments.
 *
 * `baseline` is the run's origin snapshot for `probe_baseline` assertions, or
 * NULL when no case in the run carries one. It is owned by the caller and
 * outlives every case, which is the whole point of the directive.
 */
static int
run_case(const test_case *tc, const json_value *baseline)
{
    char           errbuf[512];
    char           why[512];
    int            ok = 1;
    size_t         i;
    json_value    *before = NULL;
    http_response  resp;

    long           log_mark = 0;
    int            want_log = (tc->n_no_logs > 0 || tc->n_grep_logs > 0);

    if (tc->request_len == 0) {
        printf("# no send line in case \"%s\"\n", tc->name);
        return 0;
    }

    /*
     * The log mark is taken before ANYTHING the case does -- fault arming and
     * the before-snapshot included -- so a line those provoke is attributed to
     * this case, not silently to nobody. A missing path is a failure, not a
     * skip: a log assertion that quietly cannot run reads as a pass, which is
     * the exact failure mode assert.h exists to rule out.
     */
    if (want_log) {
        if (opt_error_log == NULL) {
            printf("# case \"%s\" has no_error_log/grep_error_log but no "
                   "error-log path is configured (-e or PROBER_ERROR_LOG)\n",
                   tc->name);
            return 0;
        }

        log_mark = error_log_mark();
    }

    if (tc->fault != NULL
        && arm_fault(tc->fault, tc->source, errbuf, sizeof(errbuf)) != 0)
    {
        printf("# %s\n", errbuf);
        return 0;
    }

    /*
     * The before-snapshot is taken AFTER arming, so a fault counter reset does
     * not show up as a delta of its own, and immediately before the send, so
     * nothing but the case's own request sits between the two reads.
     *
     * Taken for EVERY case, not only those carrying a delta assertion: the pid
     * comparison below applies to all of them, and a case with no delta line is
     * exactly the one that would otherwise report a clean pass over a worker
     * that died and was replaced mid-run.
     */
    before = fetch_probe(errbuf, sizeof(errbuf));

    if (before == NULL) {
        printf("# %s\n", errbuf);
        return 0;
    }

    if (http_request(opt_host, opt_port, tc->request, tc->request_len,
                     opt_timeout_ms, tc->source,
                     tc->pauses, tc->n_pauses, tc->shut_how, tc->abort_at,
                     tc->hold_ms, &tc->recv_opt, tc->saw_close_within,
                     tc->idle_ms, &resp,
                     errbuf, sizeof(errbuf)) != 0)
    {
        printf("# request failed: %s\n", errbuf);
        json_free(before);
        return 0;
    }

    if (opt_verbose) {
        printf("# <- status %d, %zu body bytes\n", resp.status, resp.body_len);
    }

    /*
     * Decode before any oracle runs, and fail the case outright on a framing
     * error rather than letting the body expectations run anyway. Those
     * assertions would fall back to the raw wire bytes -- which still contain
     * the chunk size lines -- so a `body~` looking for text that happens to sit
     * inside a badly framed chunk would PASS on a response the server got
     * wrong. The framing verdict has to gate the body verdict.
     */
    if (tc->dechunk) {
        http_dechunk(&resp);

        if (resp.dechunk_status != HTTP_DECHUNK_OK) {
            printf("# dechunk: %s\n", http_dechunk_reason(resp.dechunk_status));
            ok = 0;
        }
    }

    /*
     * gunzip runs AFTER dechunk (a chunked gzip body must be de-framed before
     * its stream is coherent) and, like dechunk, fails the case outright on a
     * decode error rather than letting the body oracles fall back to the
     * compressed wire bytes -- a `body~` searching those would PASS on a
     * response whose stream the server truncated or corrupted.
     */
    if (tc->gunzip) {
        http_gunzip(&resp);

        if (resp.gunzip_status != HTTP_GUNZIP_OK) {
            printf("# gunzip: %s\n", http_gunzip_reason(resp.gunzip_status));
            ok = 0;
        }
    }

    /*
     * json_sort runs LAST of the body transforms: it canonicalizes whatever the
     * dechunk/gunzip tiers left as the body, so a body_sha256 assertion over the
     * result is independent of the key order the server emitted. Like the tiers
     * above it gates the body verdict -- a body that will not parse as JSON
     * fails the case outright rather than letting a body oracle fall back to the
     * un-canonicalized bytes and PASS a hash it should not.
     */
    if (tc->json_sort) {
        http_json_sort(&resp);

        if (resp.json_sort_status != HTTP_JSON_SORT_OK) {
            printf("# json_sort: %s\n",
                   http_json_sort_reason(resp.json_sort_status));
            ok = 0;
        }
    }

    for (i = 0; i < tc->n_expects; i++) {
        if (!eval_expect(&tc->expects[i], &resp, why, sizeof(why))) {
            printf("# %s\n", why);
            ok = 0;
        }
    }

    if (tc->saw_close_within
        && !eval_close_within(&resp, tc->close_within_ms, why, sizeof(why)))
    {
        printf("# %s\n", why);
        ok = 0;
    }

    if (tc->saw_idle
        && !eval_idle(&resp, tc->idle_ms, why, sizeof(why)))
    {
        printf("# %s\n", why);
        ok = 0;
    }

    http_response_free(&resp);

    if (tc->n_probes > 0) {
        json_value *doc = fetch_probe(errbuf, sizeof(errbuf));

        if (doc == NULL) {
            printf("# %s\n", errbuf);
            json_free(before);
            return 0;
        }

        for (i = 0; i < tc->n_probes; i++) {
            if (!eval_probe(doc, &tc->probes[i], why, sizeof(why))) {
                printf("# %s\n", why);
                ok = 0;
            }
        }

        json_free(doc);
    }

    /*
     * Worker survival, for every case. Checked before any delta retry loop and
     * without retries of its own: a respawned worker never settles back to the
     * pid that served the before-snapshot, so re-reading could only turn a real
     * failure into a slower one. Its own probe read, because the delta loop
     * below is conditional and this must not be.
     *
     * `pid_may_change` selects which invariant is asserted -- same worker, or
     * merely same master -- but never whether one is. A case that spans a
     * reload still has to answer for the master it came back under.
     */
    {
        json_value *now = fetch_probe(errbuf, sizeof(errbuf));

        if (now == NULL) {
            printf("# %s\n", errbuf);
            json_free(before);
            return 0;
        }

        if (!eval_pid_stable(before, now, tc->pid_may_change, why,
                             sizeof(why)))
        {
            printf("# %s\n", why);
            ok = 0;
        }

        json_free(now);
    }

    if (tc->n_deltas > 0 || tc->n_baselines > 0) {
        int try;
        int settled = 0;

        for (try = 0; try < DELTA_SETTLE_TRIES && !settled; try++) {
            json_value *after;

            if (try > 0) {
                usleep(DELTA_SETTLE_US);
            }

            after = fetch_probe(errbuf, sizeof(errbuf));

            if (after == NULL) {
                printf("# %s\n", errbuf);
                json_free(before);
                return 0;
            }

            settled = 1;
            why[0] = '\0';

            for (i = 0; i < tc->n_deltas; i++) {
                char one[512];

                if (!eval_delta(before, after, &tc->deltas[i], "delta", one,
                                sizeof(one)))
                {
                    settled = 0;

                    /* Keep only the first failure of the last attempt: the
                     * retries exist to let a close land, so the interesting
                     * diagnostic is the one that survived them. */
                    if (why[0] == '\0') {
                        snprintf(why, sizeof(why), "%s", one);
                    }
                }
            }

            /*
             * Baselines judge the SAME after-snapshot, inside the same retry
             * loop: a connection closing late moves a baseline exactly as it
             * moves a delta, so evaluating them outside the loop would report
             * a close race as a leak on precisely the assertion written to
             * find leaks.
             */
            for (i = 0; i < tc->n_baselines; i++) {
                char one[512];

                if (!eval_delta(baseline, after, &tc->baselines[i],
                                "probe_baseline", one, sizeof(one)))
                {
                    settled = 0;

                    if (why[0] == '\0') {
                        snprintf(why, sizeof(why), "%s", one);
                    }
                }
            }

            json_free(after);
        }

        if (!settled) {
            printf("# %s (unchanged over %d re-reads, so not a close race)\n",
                   why, DELTA_SETTLE_TRIES);
            ok = 0;
        }
    }

    /*
     * Log assertions come last, after the delta settle loop: by then the
     * server has finished everything this case provoked, so the slice is as
     * complete as it will get without waiting on purpose. An empty slice is
     * evaluated, not skipped -- it is exactly what every no_error_log hopes
     * for and what every grep_error_log must be able to fail on.
     */
    if (want_log) {
        size_t  slice_len = 0;
        char   *slice = read_log_slice(log_mark, &slice_len);

        for (i = 0; i < tc->n_no_logs; i++) {
            if (slice != NULL
                && log_lines_match(slice, slice_len, &tc->no_logs[i].re))
            {
                printf("# error log matches /%s/, expected no line to\n",
                       tc->no_logs[i].pattern);
                ok = 0;
            }
        }

        for (i = 0; i < tc->n_grep_logs; i++) {
            if (slice == NULL
                || !log_lines_match(slice, slice_len, &tc->grep_logs[i].re))
            {
                printf("# no error-log line matches /%s/ during this case\n",
                       tc->grep_logs[i].pattern);
                ok = 0;
            }
        }

        free(slice);
    }

    json_free(before);

    return ok;
}


static void
usage(void)
{
    fprintf(stderr,
            "usage: prober [-H host] [-p port] [-u probe-uri] [-t ms]\n"
            "              [-e error-log] [-v] [--check]"
            " <rulefile> [rulefile ...]\n"
            "  -e (or PROBER_ERROR_LOG) names the server error log, needed\n"
            "     by the no_error_log / grep_error_log directives\n"
            "  --check parses the rule files and exits without connecting;\n"
            "     nonzero status means a rule file is malformed\n");
    exit(2);
}


int
main(int argc, char **argv)
{
    int         i, argi, failures = 0, total = 0;
    size_t      n = 0, c;
    test_case  *cases;
    json_value *baseline = NULL;

    for (argi = 1; argi < argc; argi++) {
        if (argv[argi][0] != '-') {
            break;
        }

        if (strcmp(argv[argi], "-v") == 0) {
            opt_verbose = 1;
            continue;
        }

        /* Argument-less, so it must be handled before the "flag needs a value"
         * guard below rejects it as the last word on the command line. */
        if (strcmp(argv[argi], "--check") == 0) {
            opt_check = 1;
            continue;
        }

        if (argi + 1 >= argc) {
            usage();
        }

        if (strcmp(argv[argi], "-H") == 0) {
            opt_host = argv[++argi];

        } else if (strcmp(argv[argi], "-p") == 0) {
            long port = xstrtol(argv[++argi], "-p");

            if (port < 1 || port > 65535) {
                die("-p: port %ld is outside 1-65535", port);
            }

            opt_port = (int) port;

        } else if (strcmp(argv[argi], "-u") == 0) {
            opt_probe_uri = argv[++argi];

        } else if (strcmp(argv[argi], "-e") == 0) {
            opt_error_log = argv[++argi];

        } else if (strcmp(argv[argi], "-t") == 0) {
            long timeout = xstrtol(argv[++argi], "-t");

            /*
             * A zero timeout is not a valid "wait forever" here -- it is
             * SO_RCVTIMEO's "block indefinitely", which would hang the suite
             * on a server that never answers rather than failing the case.
             */
            if (timeout < 1 || timeout > INT_MAX) {
                die("-t: timeout %ld ms is outside 1-%d", timeout, INT_MAX);
            }

            opt_timeout_ms = (int) timeout;

        } else {
            usage();
        }
    }

    if (argi >= argc) {
        usage();
    }

    /* The flag wins over the environment: run.sh exports PROBER_ERROR_LOG for
     * every run, and a -e given explicitly is the more specific intent. */
    if (opt_error_log == NULL) {
        const char *env = getenv("PROBER_ERROR_LOG");

        if (env != NULL && *env != '\0') {
            opt_error_log = env;
        }
    }

    cases = calloc(MAX_CASES, sizeof(test_case));
    if (cases == NULL) {
        die("out of memory");
    }

    /*
     * Every rule file is parsed before the first request goes out. A syntax
     * error found halfway through a run would truncate the TAP stream, and a
     * consumer reading a short plan cannot tell that from a crash.
     */
    for (i = argi; i < argc; i++) {
        n += load_rules(argv[i], cases + n, MAX_CASES - n);
    }

    /*
     * A close deadline at or past the read timeout can never be missed.
     *
     * rules.c caps the directive at MAX_CLOSE_WITHIN_MS, but that is a
     * compile-time constant and the timeout is a RUNTIME value (-t, default
     * 5000), so the parser cannot see the relationship: `expect_close_within
     * 8000` parses fine and is unfalsifiable under the default timeout. The
     * read gives up first, every such case reports HTTP_CLOSE_TIMEOUT whatever
     * the server did, and the assertion is a gate that cannot go red -- the
     * exact failure the ceiling exists to prevent, reached by the one path the
     * ceiling cannot cover.
     *
     * Checked here, after load, because this is the first point where both
     * numbers are known. Fatal rather than a per-case failure: it is a mistake
     * in how the run was invoked, not a verdict about the server, and a case
     * that cannot fail must not be allowed to report ok. Deliberately before
     * the --check return, so `--check -t N` validates the combination too.
     */
    for (c = 0; c < n; c++) {
        if (cases[c].saw_close_within
            && cases[c].close_within_ms >= opt_timeout_ms)
        {
            die("case \"%s\": expect_close_within %ld is at or past the "
                "%d ms read timeout, so the read would give up first and the "
                "assertion could never fail -- lower the deadline or raise -t",
                cases[c].name != NULL ? cases[c].name : "(unnamed)",
                cases[c].close_within_ms, opt_timeout_ms);
        }
    }

    /*
     * An idle wait at or past the read timeout is rejected too, but for a
     * different and weaker reason -- worth stating plainly so this is not read
     * as the same bug as the one above.
     *
     * The idle wait POLLS, and poll() answers to its own deadline: SO_RCVTIMEO
     * never applies to it, so a long wait is not truncated and the assertion
     * remains perfectly falsifiable. Nothing is silently wrong.
     *
     * What is wrong is the rule file. `-t` reads as the ceiling on how long any
     * one case may spend on the wire, and a case that quietly parks for longer
     * than it breaks that expectation -- the run stalls somewhere the operator
     * has no reason to look. Rejecting it keeps one number meaning one thing.
     */
    for (c = 0; c < n; c++) {
        if (cases[c].saw_idle
            && cases[c].idle_ms >= opt_timeout_ms)
        {
            die("case \"%s\": expect_idle %ld is at or past the %d ms read "
                "timeout, so the case would outlast the per-request budget -- "
                "lower the wait or raise -t",
                cases[c].name != NULL ? cases[c].name : "(unnamed)",
                cases[c].idle_ms, opt_timeout_ms);
        }
    }

    /*
     * --check stops here. load_rules() dies on the first malformed directive,
     * so reaching this point IS the pass: every file parsed and every case
     * carries a coherent set of directives. Reported on stdout so a caller can
     * see which files contributed how much; the exit status is the verdict.
     */
    if (opt_check) {
        printf("# %zu cases parsed from %d rule file%s\n",
               n, argc - argi, (argc - argi) == 1 ? "" : "s");

        for (c = 0; c < n; c++) {
            case_free(&cases[c]);
        }

        free(cases);

        return 0;
    }

    /*
     * AUD-08: a normal run with zero cases is a FALSE GREEN. load_rules() can
     * legitimately yield nothing -- a blank file, a comment-only file, a glob
     * that matched files carrying no case -- and printing `1..0` then exiting 0
     * reports a passing suite that asserted nothing. A typo, a merge conflict or
     * a generated-empty rules file would silently remove coverage while CI
     * stayed green. The informational zero result belongs only to --check (which
     * returned above); in an execution run an empty plan is fatal.
     */
    if (n == 0) {
        die("no cases to run: the rule file set parsed to an empty plan "
            "(blank, comment-only or an empty glob) -- a normal run asserts "
            "nothing and would report a false pass; use --check to inspect a "
            "zero-case set on purpose");
    }

    /*
     * The origin snapshot for `probe_baseline`, read once before any case runs
     * and held for the whole run.
     *
     * Read only when some case asks for it, so a run without the directive
     * issues no extra request. A failed read is FATAL rather than a per-case
     * failure: without an origin every probe_baseline in the file would have
     * nothing to subtract from, and silently dropping them would turn off
     * exactly the assertions written to catch a slow leak. Fatal before the
     * plan line, so the run is unambiguously aborted rather than reported as a
     * suite whose cases happened to pass.
     */
    for (c = 0; c < n; c++) {
        if (cases[c].n_baselines > 0) {
            char errbuf[512];

            baseline = fetch_probe(errbuf, sizeof(errbuf));

            if (baseline == NULL) {
                die("probe_baseline needs an origin snapshot: %s", errbuf);
            }

            break;
        }
    }

    printf("1..%zu\n", n);

    for (c = 0; c < n; c++) {
        int ok = run_case(&cases[c], baseline);

        total++;

        if (cases[c].xfail) {
            /*
             * TAP's TODO convention: an xfail case that fails does not fail
             * the suite -- it is expected, so `failures` is not incremented
             * and the line reads "not ok N # TODO <reason>". A case that
             * unexpectedly PASSES is reported as "ok N # TODO <reason>"
             * rather than plain "ok N": most TAP consumers (prove included)
             * surface that distinctly as "unexpectedly succeeded", which is
             * the signal that the annotation is stale and should come off.
             * Either way the annotation itself, not the pass/fail bit, is
             * what keeps the suite green.
             */
            printf("%s %zu - %s # TODO%s%s\n",
                   ok ? "ok" : "not ok", c + 1, cases[c].name,
                   cases[c].xfail_reason ? " " : "",
                   cases[c].xfail_reason ? cases[c].xfail_reason : "");
            fflush(stdout);
            continue;
        }

        if (!ok) {
            failures++;
        }

        printf("%s %zu - %s\n", ok ? "ok" : "not ok", c + 1, cases[c].name);
        fflush(stdout);
    }

    for (c = 0; c < n; c++) {
        case_free(&cases[c]);
    }

    free(cases);
    json_free(baseline);

    if (failures > 0) {
        printf("# %d of %d cases failed\n", failures, total);
    }

    return failures > 0 ? 1 : 0;
}
