/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * backend.c -- see backend.h.
 */

/* strtok_r() is POSIX, not C11, and the build asks for -std=c11 strictly. */
#define _GNU_SOURCE

#include "backend.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* ---- the store ------------------------------------------------------------ */

const backend_entry *
backend_get(const backend_script *s, const char *key)
{
    size_t i;

    for (i = 0; i < BACKEND_MAX_ENTRIES; i++) {
        if (s->entries[i].used && strcmp(s->entries[i].key, key) == 0) {
            return &s->entries[i];
        }
    }

    return NULL;
}


void
backend_set(backend_script *s, const char *key, const unsigned char *value,
            size_t len)
{
    size_t i, slot = BACKEND_MAX_ENTRIES;

    if (strlen(key) >= BACKEND_MAX_KEY) {
        die("backend: key \"%s\" is longer than %d bytes", key,
            BACKEND_MAX_KEY - 1);
    }

    if (len > BACKEND_MAX_VALUE) {
        die("backend: value for \"%s\" is %zu bytes, over the %d byte limit",
            key, len, BACKEND_MAX_VALUE);
    }

    /* Overwrite in place when the key exists; otherwise take the first free
     * slot. Scanning for the existing key FIRST matters: taking a free slot
     * without checking would leave two entries with the same name, and which
     * one a later get() found would depend on slot order rather than on which
     * set() came last. */
    for (i = 0; i < BACKEND_MAX_ENTRIES; i++) {
        if (s->entries[i].used && strcmp(s->entries[i].key, key) == 0) {
            slot = i;
            break;
        }

        if (!s->entries[i].used && slot == BACKEND_MAX_ENTRIES) {
            slot = i;
        }
    }

    if (slot == BACKEND_MAX_ENTRIES) {
        die("backend: store is full (max %d entries)", BACKEND_MAX_ENTRIES);
    }

    if (!s->entries[slot].used) {
        s->n_entries++;
    }

    snprintf(s->entries[slot].key, sizeof(s->entries[slot].key), "%s", key);
    memcpy(s->entries[slot].value, value, len);
    s->entries[slot].value_len = len;
    s->entries[slot].used = 1;
}


int
backend_delete(backend_script *s, const char *key)
{
    size_t i;

    for (i = 0; i < BACKEND_MAX_ENTRIES; i++) {
        if (s->entries[i].used && strcmp(s->entries[i].key, key) == 0) {
            s->entries[i].used = 0;
            s->entries[i].value_len = 0;
            s->n_entries--;
            return 1;
        }
    }

    return 0;
}


void
backend_flush_all(backend_script *s)
{
    size_t i;

    for (i = 0; i < BACKEND_MAX_ENTRIES; i++) {
        s->entries[i].used = 0;
        s->entries[i].value_len = 0;
    }

    s->n_entries = 0;
}


/* ---- fault lookup --------------------------------------------------------- */

const backend_fault *
backend_fault_for(const backend_script *s, const char *cmd, long nth)
{
    size_t               i;
    const backend_fault *wildcard = NULL;

    for (i = 0; i < s->n_faults; i++) {
        const backend_fault *f = &s->faults[i];

        if (strcmp(f->cmd, cmd) != 0) {
            continue;
        }

        if (f->nth == nth) {
            /* An exact occurrence match is the most specific statement the
             * script can make, so it wins immediately -- that is what lets a
             * file say "every get lies, except the third one, which resets". */
            return f;
        }

        if (f->nth == BACKEND_NTH_ANY && wildcard == NULL) {
            wildcard = f;
        }
    }

    return wildcard;
}


/* ---- script parser -------------------------------------------------------- */

/*
 * Split "key=value" at the first '='. Returns the value, or NULL when the token
 * carries no '=' at all.
 */
static char *
kv_split(char *tok, char **key)
{
    char *eq = strchr(tok, '=');

    if (eq == NULL) {
        return NULL;
    }

    *eq = '\0';
    *key = tok;

    return eq + 1;
}


static backend_action
action_from_name(const char *name, const char *file, int lineno)
{
    if (strcmp(name, "truncate") == 0)      return BACKEND_ACT_TRUNCATE;
    if (strcmp(name, "lie_bytes") == 0)     return BACKEND_ACT_LIE_BYTES;
    if (strcmp(name, "rst") == 0)           return BACKEND_ACT_RST;
    if (strcmp(name, "accept_close") == 0)  return BACKEND_ACT_ACCEPT_CLOSE;
    if (strcmp(name, "drip") == 0)          return BACKEND_ACT_DRIP;
    if (strcmp(name, "close_after") == 0)   return BACKEND_ACT_CLOSE_AFTER;
    if (strcmp(name, "raw") == 0)           return BACKEND_ACT_RAW;

    if (strcmp(name, "cursor_never_zero") == 0) {
        return BACKEND_ACT_CURSOR_NEVER_ZERO;
    }

    /*
     * Fatal, never a skip. A dropped fault leaves the scenario testing the
     * happy path under a name that claims otherwise, and it passes -- see the
     * note on backend_load() in backend.h.
     */
    die("%s:%d: unknown fault action \"%s\"", file, lineno, name);
}


/*
 * Parse `on=<cmd>:<nth>` into the fault. `<nth>` is 1-based, or `*`.
 */
static void
parse_on(backend_fault *f, char *value, const char *file, int lineno)
{
    char *colon = strrchr(value, ':');

    if (colon == NULL) {
        /* No occurrence given at all: `on=idle` reads naturally and there is
         * only ever one idle condition per connection, so treat a bare command
         * as "every occurrence" rather than rejecting it. */
        f->cmd = xstrdup(value);
        f->nth = BACKEND_NTH_ANY;
        return;
    }

    *colon = '\0';

    if (*value == '\0') {
        die("%s:%d: fault on= has an empty command", file, lineno);
    }

    f->cmd = xstrdup(value);

    if (strcmp(colon + 1, "*") == 0) {
        f->nth = BACKEND_NTH_ANY;
        return;
    }

    f->nth = xstrtol(colon + 1, "fault occurrence");

    /*
     * Occurrences are 1-based because they are ordinals a script author counts
     * off in words -- "the third get". Accepting 0 would silently never match,
     * which is a fault that reads as configured and behaves as absent.
     */
    if (f->nth < 1) {
        die("%s:%d: fault occurrence %ld is not 1-based", file, lineno, f->nth);
    }
}


/*
 * Validate that a parsed fault carries the parameters its action requires, and
 * none that contradict it.
 *
 * This runs after the whole stanza is read rather than per-token, because the
 * parameters may appear in any order. The check exists because a missing
 * parameter otherwise defaults to zero, and every one of these actions is a
 * no-op at zero: `truncate after=0` cuts before the first byte (which is a
 * reset by another name), `drip bytes=0` makes no progress at all, and
 * `close_after ms=0` closes instantly rather than when idle. All three would
 * run, none would do what the script says, and the scenario would report on
 * behaviour nobody asked for.
 */
static void
validate_fault(const backend_fault *f, int have_after, int have_delta,
               int have_bytes, int have_ms, int have_data,
               const char *file, int lineno)
{
    switch (f->action) {
    case BACKEND_ACT_TRUNCATE:
        if (!have_after) {
            die("%s:%d: action=truncate needs after=<bytes>", file, lineno);
        }
        if (f->after < 0) {
            die("%s:%d: truncate after=%ld is negative", file, lineno,
                f->after);
        }
        break;

    case BACKEND_ACT_LIE_BYTES:
        if (!have_delta) {
            die("%s:%d: action=lie_bytes needs delta=<signed>", file, lineno);
        }
        if (f->delta == 0) {
            /* A delta of zero produces a byte-identical correct reply, so the
             * fault is indistinguishable from its own absence. */
            die("%s:%d: lie_bytes delta=0 does not lie", file, lineno);
        }
        break;

    case BACKEND_ACT_DRIP:
        if (!have_bytes || !have_ms) {
            die("%s:%d: action=drip needs bytes=<n> and ms=<n>", file, lineno);
        }
        if (f->bytes < 1) {
            die("%s:%d: drip bytes=%ld makes no progress", file, lineno,
                f->bytes);
        }
        if (f->ms < 1 || f->ms > BACKEND_MAX_MS) {
            die("%s:%d: drip ms=%ld out of range (1..%d)", file, lineno,
                f->ms, BACKEND_MAX_MS);
        }
        break;

    case BACKEND_ACT_CLOSE_AFTER:
        if (!have_ms) {
            die("%s:%d: action=close_after needs ms=<n>", file, lineno);
        }
        if (f->ms < 1 || f->ms > BACKEND_MAX_MS) {
            die("%s:%d: close_after ms=%ld out of range (1..%d)", file, lineno,
                f->ms, BACKEND_MAX_MS);
        }
        break;

    case BACKEND_ACT_RAW:
        if (!have_data) {
            die("%s:%d: action=raw needs data=<bytes>", file, lineno);
        }
        break;

    case BACKEND_ACT_RST:
    case BACKEND_ACT_ACCEPT_CLOSE:
    case BACKEND_ACT_CURSOR_NEVER_ZERO:
        /*
         * These take no parameters. Rejecting a parameter rather than ignoring
         * it: `action=rst after=8` is a script author asking for a truncation
         * and getting an immediate reset, and silence there would leave them
         * reading a passing scenario that never tested what they wrote.
         */
        if (have_after || have_delta || have_bytes || have_ms || have_data) {
            die("%s:%d: this action takes no parameters", file, lineno);
        }
        break;

    default:
        die("%s:%d: unhandled action", file, lineno);
    }
}


static void
parse_fault(backend_script *s, char *arg, const char *file, int lineno)
{
    backend_fault *f;
    char          *tok, *save = NULL;
    int            have_action = 0, have_on = 0;
    int            have_after = 0, have_delta = 0, have_bytes = 0;
    int            have_ms = 0, have_data = 0;

    if (s->n_faults >= BACKEND_MAX_FAULTS) {
        die("%s:%d: too many faults (max %d)", file, lineno,
            BACKEND_MAX_FAULTS);
    }

    f = &s->faults[s->n_faults];
    memset(f, 0, sizeof(*f));
    f->nth = BACKEND_NTH_ANY;

    /*
     * `data=` is handled before tokenising because its value is raw bytes that
     * may legitimately contain spaces, and strtok_r would cut it at the first
     * one. Everything up to `data=` is whitespace-separated key=value; the rest
     * of the line after `data=` is the value, verbatim.
     */
    {
        char *data = strstr(arg, "data=");

        if (data != NULL) {
            size_t cap = 0;

            /* Only treat it as the data parameter when it starts a token,
             * rather than appearing inside another value. */
            if (data == arg || isspace((unsigned char) data[-1])) {
                append_escaped(&f->raw, &f->raw_len, &cap, data + 5,
                               "raw reply");
                have_data = 1;

                /* Cut the line here so the tokeniser below never sees it. */
                *data = '\0';
            }
        }
    }

    for (tok = strtok_r(arg, " \t", &save);
         tok != NULL;
         tok = strtok_r(NULL, " \t", &save))
    {
        char *key = NULL;
        char *value = kv_split(tok, &key);

        if (value == NULL) {
            die("%s:%d: fault token \"%s\" is not key=value", file, lineno,
                tok);
        }

        if (strcmp(key, "on") == 0) {
            parse_on(f, value, file, lineno);
            have_on = 1;

        } else if (strcmp(key, "action") == 0) {
            f->action = action_from_name(value, file, lineno);
            have_action = 1;

        } else if (strcmp(key, "after") == 0) {
            f->after = xstrtol(value, "fault after");
            have_after = 1;

        } else if (strcmp(key, "delta") == 0) {
            /* xstrtol() accepts a leading '+' or '-' via strtol(), which is
             * what makes `delta=+5` and `delta=-2` both spellable. */
            f->delta = xstrtol(value, "fault delta");
            have_delta = 1;

        } else if (strcmp(key, "bytes") == 0) {
            f->bytes = xstrtol(value, "fault bytes");
            have_bytes = 1;

        } else if (strcmp(key, "ms") == 0) {
            f->ms = xstrtol(value, "fault ms");
            have_ms = 1;

        } else {
            die("%s:%d: unknown fault parameter \"%s\"", file, lineno, key);
        }
    }

    if (!have_on) {
        die("%s:%d: fault needs on=<cmd>[:<nth>]", file, lineno);
    }

    if (!have_action) {
        die("%s:%d: fault needs action=<name>", file, lineno);
    }

    validate_fault(f, have_after, have_delta, have_bytes, have_ms, have_data,
                   file, lineno);

    s->n_faults++;
}


void
backend_load(const char *file, backend_script *s)
{
    FILE *fp;
    char  line[4096];
    int   lineno = 0;
    int   have_proto = 0;

    memset(s, 0, sizeof(*s));

    fp = fopen(file, "r");
    if (fp == NULL) {
        die("cannot open backend script %s", file);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p, *directive;

        lineno++;

        p = line;
        p[strcspn(p, "\n")] = '\0';

        while (*p != '\0' && isspace((unsigned char) *p)) {
            p++;
        }

        if (*p == '\0' || *p == '#') {
            continue;
        }

        directive = p;

        while (*p != '\0' && !isspace((unsigned char) *p)) {
            p++;
        }

        if (*p != '\0') {
            *p++ = '\0';
        }

        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if (strcmp(directive, "proto") == 0) {
            char *name = trim(p);

            if (strcmp(name, "memcached") == 0) {
                s->proto = BACKEND_PROTO_MEMCACHED;

            } else if (strcmp(name, "redis") == 0) {
                s->proto = BACKEND_PROTO_REDIS;

            } else {
                die("%s:%d: unknown proto \"%s\"", file, lineno, name);
            }

            have_proto = 1;

        } else if (strcmp(directive, "seed") == 0) {
            char *key, *save = NULL, *value;

            key = strtok_r(p, " \t", &save);
            if (key == NULL) {
                die("%s:%d: seed needs a key and a value", file, lineno);
            }

            value = save;
            while (value != NULL && (*value == ' ' || *value == '\t')) {
                value++;
            }

            if (value == NULL || *value == '\0') {
                die("%s:%d: seed \"%s\" has no value", file, lineno, key);
            }

            {
                /* Seed values carry the same escapes as everything else, so a
                 * scenario can seed a value with an embedded NUL or CRLF -- the
                 * shapes a cache client is least likely to handle. */
                unsigned char *decoded = NULL;
                size_t         len = 0, cap = 0;

                append_escaped(&decoded, &len, &cap, value, "seed value");
                backend_set(s, key, decoded == NULL
                                    ? (const unsigned char *) "" : decoded,
                            len);
                free(decoded);
            }

        } else if (strcmp(directive, "fault") == 0) {
            parse_fault(s, p, file, lineno);

        } else {
            die("%s:%d: unknown directive \"%s\"", file, lineno, directive);
        }
    }

    fclose(fp);

    /*
     * The protocol is not defaulted. Guessing memcached would make a redis
     * script that forgot the line answer memcached replies to RESP commands,
     * and the resulting parse errors would point at the client rather than at
     * the missing line.
     */
    if (!have_proto) {
        die("%s: no proto directive (memcached or redis)", file);
    }
}


void
backend_free(backend_script *s)
{
    size_t i;

    for (i = 0; i < s->n_faults; i++) {
        free(s->faults[i].cmd);
        free(s->faults[i].raw);
    }

    memset(s, 0, sizeof(*s));
}


/* ---- memcached codec ------------------------------------------------------ */

/*
 * The full verb table from the memc module, so nothing a client sends gets an
 * accidental `ERROR` and a scenario ends up testing our omission rather than
 * the module. Real semantics are implemented for the four that a cache client
 * actually depends on; the rest answer in the correct SHAPE, which is all a
 * module's parser can observe of them.
 */
static int
memcached_is_storage(const char *name)
{
    return strcmp(name, "set") == 0
           || strcmp(name, "add") == 0
           || strcmp(name, "replace") == 0
           || strcmp(name, "append") == 0
           || strcmp(name, "prepend") == 0;
}


/*
 * Read the first token of `line` into `word` without writing to the line.
 *
 * These two helpers exist because completeness has to be decided before the
 * destructive tokenisation below, and a scan that mutated the buffer would
 * reintroduce exactly the bug it is here to prevent.
 */
static void
memcached_first_word(const unsigned char *line, size_t line_len, char *word,
                     size_t wordlen)
{
    size_t i = 0;

    while (i < line_len && i + 1 < wordlen
           && line[i] != ' ' && line[i] != '\r')
    {
        word[i] = (char) line[i];
        i++;
    }

    word[i] = '\0';
}


static int
memcached_line_is_storage(const unsigned char *line, size_t line_len)
{
    char word[32];
    size_t i;

    memcached_first_word(line, line_len, word, sizeof(word));

    for (i = 0; word[i] != '\0'; i++) {
        if (word[i] >= 'A' && word[i] <= 'Z') {
            word[i] = (char) (word[i] - 'A' + 'a');
        }
    }

    return memcached_is_storage(word);
}


/*
 * The declared data length of a storage command: the fourth space-separated
 * field. Returns -2 when the field is missing or not a number, so a malformed
 * length is distinguishable from a legitimately absent one.
 */
static long
memcached_declared_len(const unsigned char *line, size_t line_len)
{
    size_t i = 0, field = 0, start;
    char   num[32], *stop;
    long   v;

    /* Walk to the start of field 4 (0-based: the verb is field 0). */
    while (i < line_len && field < 4) {
        while (i < line_len && line[i] != ' ') {
            i++;
        }
        while (i < line_len && line[i] == ' ') {
            i++;
        }
        field++;
    }

    if (field < 4 || i >= line_len) {
        return -2;
    }

    start = i;

    while (i < line_len && line[i] != ' ' && line[i] != '\r') {
        i++;
    }

    if (i - start == 0 || i - start >= sizeof(num)) {
        return -2;
    }

    memcpy(num, line + start, i - start);
    num[i - start] = '\0';

    errno = 0;
    v = strtol(num, &stop, 10);

    if (*stop != '\0' || errno == ERANGE) {
        return -2;
    }

    return v;
}


long
backend_parse_memcached(unsigned char *buf, size_t len, backend_cmd *out)
{
    const unsigned char *nl;
    size_t               line_len, i;
    char                *line, *tok, *save = NULL;
    long                 scanned_len = -1;

    /* Bound on a single command line. Not a buffer size any more (the line is
     * tokenised in place), but still a limit: a client that never sends a
     * newline must not be able to grow the daemon's read buffer without end. */
    enum { MAX_LINE = 1024 };

    memset(out, 0, sizeof(*out));
    out->data_len = -1;

    nl = memchr(buf, '\n', len);
    if (nl == NULL) {
        /* No complete command line yet. Bound the wait: without this a client
         * that never sends a newline grows the read buffer without limit. */
        if (len >= MAX_LINE) {
            return -1;
        }
        return 0;
    }

    line_len = (size_t) (nl - buf);

    if (line_len >= MAX_LINE) {
        return -1;
    }

    /*
     * COMPLETENESS IS DECIDED BEFORE ANYTHING IS MUTATED.
     *
     * Tokenising below is destructive, and this parser is called repeatedly on
     * the same bytes: the caller re-invokes it as more data arrives, so a
     * return of 0 must leave the buffer exactly as it was found. The first
     * draft tokenised first and checked the data block afterwards, so a `set`
     * whose payload had not yet arrived came back 0 with its line already
     * NUL-punched -- and the retry, parsing the mangled bytes, rejected a
     * perfectly valid command as a protocol error.
     *
     * It only reproduced when the data block landed in a LATER read() than its
     * command line, which is scheduling-dependent: every local run wrote the
     * whole thing in one go and passed. CI failed on all four legs at once.
     * Hence the scan below reads the declared length WITHOUT writing, and the
     * in-place tokenisation happens only once the whole command is present.
     */
    if (memcached_line_is_storage(buf, line_len)) {
        size_t consumed, need;

        /* Kept for the bookkeeping after tokenisation. It cannot be re-derived
         * there: the field walk needs the separating spaces, and by then they
         * have been overwritten with NULs. */
        scanned_len = memcached_declared_len(buf, line_len);

        if (scanned_len == -2) {
            return -1;                       /* malformed length */
        }

        if (scanned_len < 0 || scanned_len > BACKEND_MAX_VALUE) {
            return -1;
        }

        consumed = line_len + 1;
        need = consumed + (size_t) scanned_len;

        /* The block is terminated by CRLF (or bare LF) of its own. */
        if (len < need + 1) {
            return 0;                        /* buffer untouched */
        }

        if (buf[need] != '\r' && buf[need] != '\n') {
            return -1;
        }

        if (buf[need] == '\r' && len < need + 2) {
            return 0;                        /* buffer untouched */
        }
    }

    /*
     * Tokenise the caller's buffer IN PLACE, exactly as the RESP parser does.
     *
     * The obvious alternative -- copy the line into a local and tokenise that
     * -- was the first draft and is a use-after-return: strtok_r returns
     * pointers INTO whatever it parsed, so `out->args` would point into a stack
     * buffer that dies at this function's return. The caller then read freed
     * stack, and the daemon answered `get hello` with a key of "<\x7f". It
     * survived backend_test.c because a test reads args while the parser's
     * frame is still live; only the daemon, which returns first and uses the
     * args after, could show it. The journal is what made it visible.
     *
     * Writing NULs into the caller's buffer is safe here and does not disturb a
     * following pipelined command: every NUL goes at a byte within THIS
     * command's line (a separating space, or the CR of its own terminator), and
     * the caller consumes exactly `line_len + 1` bytes on return.
     */
    line = (char *) buf;

    /* Terminate at the LF, which is part of this command and is consumed. */
    line[line_len] = '\0';

    /* Tolerate both CRLF and bare LF. A real memcached requires CRLF, but a
     * client that sends bare LF is exercising the server's leniency, not a
     * parse error we should invent. */
    if (line_len > 0 && line[line_len - 1] == '\r') {
        line[line_len - 1] = '\0';
    }

    tok = strtok_r(line, " ", &save);
    if (tok == NULL) {
        return -1;
    }

    snprintf(out->name, sizeof(out->name), "%s", tok);

    /* Fold the verb to lower case so `GET` and `get` are one command for fault
     * counting. ASCII-only rather than tolower(): the locale leg in CI found a
     * real bug where a Turkish locale made 'I' a fixed point of tolower(), and
     * a verb table consulted through the locale table would reintroduce it. */
    for (i = 0; out->name[i] != '\0'; i++) {
        if (out->name[i] >= 'A' && out->name[i] <= 'Z') {
            out->name[i] = (char) (out->name[i] - 'A' + 'a');
        }
    }

    while ((tok = strtok_r(NULL, " ", &save)) != NULL
           && out->n_args < BACKEND_MAX_ARGS)
    {
        out->args[out->n_args++] = tok;
    }

    /*
     * The data block. Its presence and its declared length were already
     * settled by the non-destructive scan above -- everything here is
     * bookkeeping on bytes known to have arrived, which is why none of it can
     * return 0 any more.
     */
    if (memcached_is_storage(out->name)) {
        size_t consumed, need;

        if (out->n_args < 4) {
            return -1;
        }

        out->data_len = scanned_len;

        consumed = line_len + 1;
        need = consumed + (size_t) scanned_len;

        /* Points into the caller's buffer, like `args`. */
        out->data = buf + consumed;

        return (long) (need + (buf[need] == '\r' ? 2 : 1));
    }

    return (long) (line_len + 1);
}


/*
 * Append to a malloc'd buffer, growing as needed. Local to the reply builders,
 * which are the only place that assembles output.
 */
static void
buf_append(unsigned char **buf, size_t *len, size_t *cap,
           const void *data, size_t n)
{
    if (*len + n > *cap) {
        unsigned char *bigger;
        size_t         want = (*cap == 0) ? 256 : *cap;

        while (want < *len + n) {
            want *= 2;
        }

        bigger = realloc(*buf, want);
        if (bigger == NULL) {
            die("out of memory");
        }

        *buf = bigger;
        *cap = want;
    }

    memcpy(*buf + *len, data, n);
    *len += n;
}


static void
buf_appendf(unsigned char **buf, size_t *len, size_t *cap, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static void
buf_appendf(unsigned char **buf, size_t *len, size_t *cap, const char *fmt, ...)
{
    char    tmp[512];
    va_list ap;
    int     n;

    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t) n >= sizeof(tmp)) {
        die("backend: reply fragment too long");
    }

    buf_append(buf, len, cap, tmp, (size_t) n);
}


void
backend_reply_memcached(backend_script *s, const backend_cmd *cmd,
                        unsigned char **out, size_t *out_len)
{
    unsigned char *buf = NULL;
    size_t         len = 0, cap = 0;

    *out = NULL;
    *out_len = 0;

    if (strcmp(cmd->name, "get") == 0 || strcmp(cmd->name, "gets") == 0) {
        size_t i;

        /* A multi-key get answers with one VALUE block per key that exists,
         * then a single END -- misses are simply absent rather than signalled,
         * which is the detail a client's miss handling most often gets wrong. */
        for (i = 0; i < cmd->n_args; i++) {
            const backend_entry *e = backend_get(s, cmd->args[i]);

            if (e == NULL) {
                continue;
            }

            buf_appendf(&buf, &len, &cap, "VALUE %s 0 %zu\r\n", e->key,
                        e->value_len);
            buf_append(&buf, &len, &cap, e->value, e->value_len);
            buf_append(&buf, &len, &cap, "\r\n", 2);
        }

        buf_append(&buf, &len, &cap, "END\r\n", 5);

    } else if (strcmp(cmd->name, "set") == 0) {
        /* Actually store it. Acknowledging a set whose payload was discarded
         * makes the NEXT get answer a miss, which reads as a cache bug in the
         * module under test rather than as a defect in the fake. */
        if (cmd->n_args >= 1 && cmd->data != NULL && cmd->data_len >= 0) {
            backend_set(s, cmd->args[0], cmd->data, (size_t) cmd->data_len);
        }

        buf_append(&buf, &len, &cap, "STORED\r\n", 8);

    } else if (memcached_is_storage(cmd->name)) {
        /* add/replace/append/prepend: correct shape, no store semantics. The
         * note in backend.h applies -- a scenario needing real add-vs-replace
         * conflict semantics wants a real daemon. */
        buf_append(&buf, &len, &cap, "STORED\r\n", 8);

    } else if (strcmp(cmd->name, "delete") == 0) {
        if (cmd->n_args > 0 && backend_delete(s, cmd->args[0])) {
            buf_append(&buf, &len, &cap, "DELETED\r\n", 9);
        } else {
            buf_append(&buf, &len, &cap, "NOT_FOUND\r\n", 11);
        }

    } else if (strcmp(cmd->name, "flush_all") == 0) {
        backend_flush_all(s);
        buf_append(&buf, &len, &cap, "OK\r\n", 4);

    } else if (strcmp(cmd->name, "version") == 0) {
        buf_append(&buf, &len, &cap, "VERSION 1.6.38-fake\r\n", 21);

    } else if (strcmp(cmd->name, "incr") == 0
               || strcmp(cmd->name, "decr") == 0)
    {
        buf_append(&buf, &len, &cap, "0\r\n", 3);

    } else if (strcmp(cmd->name, "stats") == 0) {
        buf_appendf(&buf, &len, &cap, "STAT pid 1\r\n");
        buf_appendf(&buf, &len, &cap, "STAT version 1.6.38-fake\r\n");
        buf_appendf(&buf, &len, &cap, "STAT curr_items %zu\r\n", s->n_entries);
        buf_append(&buf, &len, &cap, "END\r\n", 5);

    } else if (strcmp(cmd->name, "quit") == 0) {
        /* No reply; the server half closes on seeing this. */
        *out = NULL;
        *out_len = 0;
        return;

    } else {
        buf_append(&buf, &len, &cap, "ERROR\r\n", 7);
    }

    *out = buf;
    *out_len = len;
}


/* ---- RESP codec ----------------------------------------------------------- */

long
backend_parse_resp(unsigned char *buf, size_t len, backend_cmd *out)
{
    unsigned char *p = buf, *end = buf + len, *nl;
    long                 argc, i;
    char                 tmp[64];

    memset(out, 0, sizeof(*out));
    out->data_len = -1;

    if (len == 0) {
        return 0;
    }

    /*
     * Inline commands (a bare "PING\r\n" with no array framing) are what a
     * human typing at the socket sends, and several clients emit them for
     * simple verbs. Handling them here rather than rejecting keeps a scenario's
     * `printf | nc` smoke test honest against the same daemon the module uses.
     */
    if (*p != '*') {
        char *tok, *save = NULL;
        size_t line_len;

        nl = memchr(p, '\n', len);
        if (nl == NULL) {
            return (len >= sizeof(tmp)) ? -1 : 0;
        }

        line_len = (size_t) (nl - p);
        if (line_len >= sizeof(tmp)) {
            return -1;
        }

        memcpy(tmp, p, line_len);
        tmp[line_len] = '\0';

        if (line_len > 0 && tmp[line_len - 1] == '\r') {
            tmp[line_len - 1] = '\0';
        }

        tok = strtok_r(tmp, " ", &save);
        if (tok == NULL) {
            return -1;
        }

        snprintf(out->name, sizeof(out->name), "%s", tok);

        while ((tok = strtok_r(NULL, " ", &save)) != NULL
               && out->n_args < BACKEND_MAX_ARGS)
        {
            out->args[out->n_args++] = tok;
        }

        return (long) (line_len + 1);
    }

    /* Array header: *<count>\r\n */
    nl = memchr(p, '\n', (size_t) (end - p));
    if (nl == NULL) {
        return 0;
    }

    if ((size_t) (nl - p) >= sizeof(tmp)) {
        return -1;
    }

    memcpy(tmp, p + 1, (size_t) (nl - p - 1));
    tmp[nl - p - 1] = '\0';

    {
        char *stop;

        argc = strtol(tmp, &stop, 10);

        /* Reject trailing garbage rather than taking the prefix: "*3x" is a
         * malformed frame, and reading it as 3 would resynchronise the parser
         * onto bytes the client never meant as arguments. */
        while (*stop == '\r') {
            stop++;
        }

        if (*stop != '\0') {
            return -1;
        }
    }

    if (argc < 1 || argc > BACKEND_MAX_ARGS) {
        return -1;
    }

    p = nl + 1;

    for (i = 0; i < argc; i++) {
        long blen;

        if (p >= end || *p != '$') {
            return (p >= end) ? 0 : -1;
        }

        nl = memchr(p, '\n', (size_t) (end - p));
        if (nl == NULL) {
            return 0;
        }

        if ((size_t) (nl - p) >= sizeof(tmp)) {
            return -1;
        }

        memcpy(tmp, p + 1, (size_t) (nl - p - 1));
        tmp[nl - p - 1] = '\0';

        {
            char *stop;

            blen = strtol(tmp, &stop, 10);

            while (*stop == '\r') {
                stop++;
            }

            if (*stop != '\0') {
                return -1;
            }
        }

        if (blen < 0 || blen > BACKEND_MAX_VALUE) {
            return -1;
        }

        p = nl + 1;

        /* The bulk payload plus its CRLF must have arrived. */
        if (end - p < blen + 1) {
            return 0;
        }

        if (i == 0) {
            size_t n = (size_t) blen;

            if (n >= sizeof(out->name)) {
                n = sizeof(out->name) - 1;
            }

            memcpy(out->name, p, n);
            out->name[n] = '\0';

            {
                size_t k;

                for (k = 0; out->name[k] != '\0'; k++) {
                    if (out->name[k] >= 'A' && out->name[k] <= 'Z') {
                        out->name[k] = (char) (out->name[k] - 'A' + 'a');
                    }
                }
            }

        } else if (out->n_args < BACKEND_MAX_ARGS) {
            out->args[out->n_args++] = (char *) p;
        }

        /*
         * Advance past the payload and its terminator BEFORE NUL-terminating
         * the argument below.
         *
         * The order is load-bearing and got this wrong on the first draft. The
         * NUL goes where the payload's own CR is, so terminating first and then
         * testing `*p == '\r'` reads the byte that was just overwritten: the
         * skip does not fire, the frame is reported two bytes short, and the
         * parser resumes mid-terminator. A single GET survived that as a
         * silently truncated length, but the next command in the same buffer
         * started one byte off and the whole frame was rejected as malformed --
         * a valid client command reported as a protocol error.
         */
        p += blen;

        if (p < end && *p == '\r') {
            p++;
        }

        if (p < end && *p == '\n') {
            p++;
        }

        /*
         * Now terminate. Arguments point into the caller's buffer rather than
         * being copied, which is why a backend_cmd must not outlive the read
         * buffer -- stated in backend.h. Safe because the whole frame is
         * present by here, checked above.
         */
        if (i > 0 && out->n_args > 0) {
            out->args[out->n_args - 1][blen] = '\0';
        }
    }

    return (long) (p - buf);
}


void
backend_reply_resp(backend_script *s, const backend_cmd *cmd,
                   unsigned char **out, size_t *out_len)
{
    unsigned char *buf = NULL;
    size_t         len = 0, cap = 0;

    *out = NULL;
    *out_len = 0;

    if (strcmp(cmd->name, "get") == 0) {
        const backend_entry *e;

        if (cmd->n_args < 1) {
            buf_append(&buf, &len, &cap, "-ERR wrong number of arguments\r\n",
                       32);
            goto done;
        }

        e = backend_get(s, cmd->args[0]);

        if (e == NULL) {
            /* The nil bulk string. Distinct from an empty one ($0\r\n\r\n),
             * and a client that conflates them cannot tell a missing key from
             * a key holding "" -- a distinction cache code treats as
             * load-bearing. */
            buf_append(&buf, &len, &cap, "$-1\r\n", 5);

        } else {
            buf_appendf(&buf, &len, &cap, "$%zu\r\n", e->value_len);
            buf_append(&buf, &len, &cap, e->value, e->value_len);
            buf_append(&buf, &len, &cap, "\r\n", 2);
        }

    } else if (strcmp(cmd->name, "set") == 0) {
        if (cmd->n_args < 2) {
            buf_append(&buf, &len, &cap, "-ERR wrong number of arguments\r\n",
                       32);
            goto done;
        }

        backend_set(s, cmd->args[0], (const unsigned char *) cmd->args[1],
                    strlen(cmd->args[1]));
        buf_append(&buf, &len, &cap, "+OK\r\n", 5);

    } else if (strcmp(cmd->name, "del") == 0) {
        long n = 0;
        size_t i;

        for (i = 0; i < cmd->n_args; i++) {
            n += backend_delete(s, cmd->args[i]);
        }

        buf_appendf(&buf, &len, &cap, ":%ld\r\n", n);

    } else if (strcmp(cmd->name, "exists") == 0) {
        long n = 0;
        size_t i;

        for (i = 0; i < cmd->n_args; i++) {
            n += (backend_get(s, cmd->args[i]) != NULL);
        }

        buf_appendf(&buf, &len, &cap, ":%ld\r\n", n);

    } else if (strcmp(cmd->name, "ping") == 0) {
        buf_append(&buf, &len, &cap, "+PONG\r\n", 7);

    } else if (strcmp(cmd->name, "flushall") == 0
               || strcmp(cmd->name, "flushdb") == 0)
    {
        backend_flush_all(s);
        buf_append(&buf, &len, &cap, "+OK\r\n", 5);

    } else if (strcmp(cmd->name, "quit") == 0) {
        buf_append(&buf, &len, &cap, "+OK\r\n", 5);

    } else if (strcmp(cmd->name, "scan") == 0) {
        /*
         * SCAN over a snapshot taken at cursor 0: the whole keyspace is
         * returned in one step and the cursor goes straight back to 0. A real
         * redis may return the same key twice across a resharding scan, which
         * is a behaviour worth testing -- but only deliberately, via
         * cursor_never_zero, rather than as an accident of this implementation.
         */
        size_t i;
        size_t n = 0;

        for (i = 0; i < BACKEND_MAX_ENTRIES; i++) {
            n += (size_t) (s->entries[i].used != 0);
        }

        buf_append(&buf, &len, &cap, "*2\r\n", 4);
        buf_append(&buf, &len, &cap, "$1\r\n0\r\n", 7);
        buf_appendf(&buf, &len, &cap, "*%zu\r\n", n);

        for (i = 0; i < BACKEND_MAX_ENTRIES; i++) {
            if (!s->entries[i].used) {
                continue;
            }

            buf_appendf(&buf, &len, &cap, "$%zu\r\n%s\r\n",
                        strlen(s->entries[i].key), s->entries[i].key);
        }

    } else {
        buf_appendf(&buf, &len, &cap, "-ERR unknown command '%s'\r\n",
                    cmd->name);
    }

done:

    *out = buf;
    *out_len = len;
}


/* ---- lie_bytes ------------------------------------------------------------ */

unsigned char *
backend_apply_lie(backend_proto proto, const unsigned char *in, size_t in_len,
                  long delta, size_t *out_len)
{
    unsigned char *out = NULL;
    size_t         len = 0, cap = 0;
    const unsigned char *nl;
    char           head[256];
    size_t         head_len;

    *out_len = 0;

    /*
     * Both protocols declare the length on the FIRST line of the reply --
     * memcached as the fourth field of `VALUE <key> <flags> <bytes>`, RESP as
     * the number after `$`. Rewriting only that line leaves the payload
     * untouched, which is the point: the test is about the client trusting a
     * declared length, so the bytes that follow must remain exactly what a
     * correct reply would have carried.
     */
    nl = memchr(in, '\n', in_len);
    if (nl == NULL) {
        return NULL;
    }

    head_len = (size_t) (nl - in) + 1;

    if (head_len >= sizeof(head)) {
        return NULL;
    }

    memcpy(head, in, head_len);
    head[head_len] = '\0';

    if (proto == BACKEND_PROTO_MEMCACHED) {
        char   key[BACKEND_MAX_KEY];
        long   flags, bytes;

        if (sscanf(head, "VALUE %255s %ld %ld", key, &flags, &bytes) != 3) {
            return NULL;
        }

        if (bytes + delta < 0) {
            return NULL;
        }

        buf_appendf(&out, &len, &cap, "VALUE %s %ld %ld\r\n", key, flags,
                    bytes + delta);

    } else {
        long bytes;

        if (head[0] != '$') {
            return NULL;
        }

        bytes = strtol(head + 1, NULL, 10);

        if (bytes + delta < 0) {
            return NULL;
        }

        buf_appendf(&out, &len, &cap, "$%ld\r\n", bytes + delta);
    }

    buf_append(&out, &len, &cap, in + head_len, in_len - head_len);

    *out_len = len;

    return out;
}
