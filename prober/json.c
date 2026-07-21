/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * json.c -- see json.h.
 */

#include "json.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    const char  *p;
    const char  *end;
    const char  *err;
    int          depth;
} jparse;


static json_value *parse_value(jparse *s);


static json_value *
value_new(json_type type)
{
    json_value *v = calloc(1, sizeof(json_value));

    if (v != NULL) {
        v->type = type;
    }

    return v;
}


void
json_free(json_value *v)
{
    size_t i;

    if (v == NULL) {
        return;
    }

    for (i = 0; i < v->count; i++) {
        if (v->keys != NULL) {
            free(v->keys[i]);
        }
        json_free(v->items[i]);
    }

    free(v->keys);
    free(v->items);
    free(v->string);
    free(v);
}


static void
skip_ws(jparse *s)
{
    while (s->p < s->end
           && (*s->p == ' ' || *s->p == '\t' || *s->p == '\n' || *s->p == '\r'))
    {
        s->p++;
    }
}


static int
literal(jparse *s, const char *word)
{
    size_t n = strlen(word);

    if ((size_t) (s->end - s->p) < n || memcmp(s->p, word, n) != 0) {
        return 0;
    }

    s->p += n;
    return 1;
}


/*
 * Strings: the probe emits plain ASCII plus the two-character escapes below.
 * \u is rejected rather than silently mishandled -- a harness that quietly
 * mangles input it does not understand produces wrong verdicts, and the
 * producer is ours, so an unexpected \u means the document changed and the
 * parser should be updated to match.
 */
static char *
parse_string_raw(jparse *s)
{
    char    *out;
    size_t   len = 0, cap = 32;

    if (s->p >= s->end || *s->p != '"') {
        s->err = "expected string";
        return NULL;
    }

    s->p++;

    out = malloc(cap);
    if (out == NULL) {
        s->err = "out of memory";
        return NULL;
    }

    while (s->p < s->end && *s->p != '"') {
        char c = *s->p++;

        if (c == '\\') {
            if (s->p >= s->end) {
                break;
            }

            switch (*s->p++) {
            case '"':  c = '"';  break;
            case '\\': c = '\\'; break;
            case '/':  c = '/';  break;
            case 'b':  c = '\b'; break;
            case 'f':  c = '\f'; break;
            case 'n':  c = '\n'; break;
            case 'r':  c = '\r'; break;
            case 't':  c = '\t'; break;
            default:
                s->err = "unsupported string escape";
                free(out);
                return NULL;
            }

        } else if ((unsigned char) c < 0x20) {
            /* RFC 8259 requires C0 controls to be escaped. Accepting a raw one
             * would let a probe document with a stray newline or NUL inside a
             * string still parse, which is the shape a rendering bug takes. */
            s->err = "raw control character in string";
            free(out);
            return NULL;
        }

        if (len + 1 >= cap) {
            char *bigger;

            cap *= 2;
            bigger = realloc(out, cap);
            if (bigger == NULL) {
                s->err = "out of memory";
                free(out);
                return NULL;
            }
            out = bigger;
        }

        out[len++] = c;
    }

    if (s->p >= s->end || *s->p != '"') {
        s->err = "unterminated string";
        free(out);
        return NULL;
    }

    s->p++;
    out[len] = '\0';

    return out;
}


static int
container_push(json_value *v, char *key, json_value *item)
{
    json_value **items;
    char       **keys;

    items = realloc(v->items, (v->count + 1) * sizeof(json_value *));
    if (items == NULL) {
        return -1;
    }
    v->items = items;

    if (key != NULL) {
        keys = realloc(v->keys, (v->count + 1) * sizeof(char *));
        if (keys == NULL) {
            /* v->items was already grown, but count is not bumped, so the slot
             * is not live and the caller still owns `item`. Say so by failing
             * before anything is published rather than half-committing. */
            return -1;
        }
        v->keys = keys;
        v->keys[v->count] = key;
    }

    v->items[v->count] = item;
    v->count++;

    return 0;
}


static json_value *
parse_object(jparse *s)
{
    json_value *v = value_new(JSON_OBJECT);

    if (v == NULL) {
        s->err = "out of memory";
        return NULL;
    }

    s->p++;                                                   /* consume '{' */
    skip_ws(s);

    if (s->p < s->end && *s->p == '}') {
        s->p++;
        return v;
    }

    for ( ;; ) {
        char       *key;
        size_t      i;
        json_value *item;

        skip_ws(s);

        key = parse_string_raw(s);
        if (key == NULL) {
            json_free(v);
            return NULL;
        }

        skip_ws(s);

        if (s->p >= s->end || *s->p != ':') {
            s->err = "expected ':' after object key";
            free(key);
            json_free(v);
            return NULL;
        }
        s->p++;

        item = parse_value(s);
        if (item == NULL) {
            free(key);
            json_free(v);
            return NULL;
        }

        /*
         * A repeated key would be invisible: json_get() returns the first
         * match, so the second value could never be asserted on. The document
         * is produced by the probe, and the way a duplicate gets there is a
         * module's zone_render hook emitting a member the generic side already
         * emitted -- a defect in the thing under test, which should surface as
         * a broken probe rather than as a value silently shadowing another.
         */
        for (i = 0; i < v->count; i++) {
            if (strcmp(v->keys[i], key) == 0) {
                s->err = "duplicate key in object";
                free(key);
                json_free(item);
                json_free(v);
                return NULL;
            }
        }

        if (container_push(v, key, item) != 0) {
            s->err = "out of memory";
            free(key);
            json_free(item);
            json_free(v);
            return NULL;
        }

        skip_ws(s);

        if (s->p < s->end && *s->p == ',') {
            s->p++;
            continue;
        }

        if (s->p < s->end && *s->p == '}') {
            s->p++;
            return v;
        }

        s->err = "expected ',' or '}' in object";
        json_free(v);
        return NULL;
    }
}


static json_value *
parse_array(jparse *s)
{
    json_value *v = value_new(JSON_ARRAY);

    if (v == NULL) {
        s->err = "out of memory";
        return NULL;
    }

    s->p++;                                                   /* consume '[' */
    skip_ws(s);

    if (s->p < s->end && *s->p == ']') {
        s->p++;
        return v;
    }

    for ( ;; ) {
        json_value *item = parse_value(s);

        if (item == NULL) {
            json_free(v);
            return NULL;
        }

        if (container_push(v, NULL, item) != 0) {
            s->err = "out of memory";
            json_free(item);
            json_free(v);
            return NULL;
        }

        skip_ws(s);

        if (s->p < s->end && *s->p == ',') {
            s->p++;
            continue;
        }

        if (s->p < s->end && *s->p == ']') {
            s->p++;
            return v;
        }

        s->err = "expected ',' or ']' in array";
        json_free(v);
        return NULL;
    }
}


/*
 * Validate a collected token against the RFC 8259 number grammar:
 *
 *     -? ( 0 | [1-9][0-9]* ) ( '.' [0-9]+ )? ( [eE] [+-]? [0-9]+ )?
 *
 * strtod() alone is far more permissive -- it takes "+1", ".5", "0x10", "inf",
 * and leading-zero forms JSON forbids. The probe renderer emits plain integers,
 * so anything else in the document means the renderer misformatted a field, and
 * a lenient parser would turn that into a silently passing assertion.
 */
static int
number_token_is_json(const char *t)
{
    const char *p = t;

    if (*p == '-') {
        p++;
    }

    if (*p == '0') {
        p++;                                    /* no leading zeros allowed */

    } else if (*p >= '1' && *p <= '9') {
        while (*p >= '0' && *p <= '9') {
            p++;
        }

    } else {
        return 0;                               /* "+1", ".5", "" */
    }

    if (*p == '.') {
        p++;

        if (*p < '0' || *p > '9') {
            return 0;                           /* "1." */
        }

        while (*p >= '0' && *p <= '9') {
            p++;
        }
    }

    if (*p == 'e' || *p == 'E') {
        p++;

        if (*p == '+' || *p == '-') {
            p++;
        }

        if (*p < '0' || *p > '9') {
            return 0;                           /* "1e", "1e+" */
        }

        while (*p >= '0' && *p <= '9') {
            p++;
        }
    }

    return *p == '\0';
}


static json_value *
parse_number(jparse *s)
{
    char        buf[64];
    char       *stop;
    size_t      n = 0;
    json_value *v;

    while (s->p < s->end
           && (strchr("-+.eE", *s->p) != NULL
               || (*s->p >= '0' && *s->p <= '9')))
    {
        /* Truncating the token and parsing the prefix would turn an absurd
         * number into a plausible one, so overflow is an error, not a clamp. */
        if (n + 1 >= sizeof(buf)) {
            s->err = "number too long";
            return NULL;
        }

        buf[n++] = *s->p++;
    }

    buf[n] = '\0';

    if (!number_token_is_json(buf)) {
        s->err = "malformed number";
        return NULL;
    }

    v = value_new(JSON_NUMBER);
    if (v == NULL) {
        s->err = "out of memory";
        return NULL;
    }

    v->number = strtod(buf, &stop);

    if (stop == buf || *stop != '\0') {
        s->err = "malformed number";
        json_free(v);
        return NULL;
    }

    /* "1e999" is grammatical JSON that strtod() turns into infinity. Infinity
     * compares as a number under every operator, so an assertion against it
     * would return a confident verdict about a value this document cannot
     * actually represent. Refuse rather than approximate. */
    if (!isfinite(v->number)) {
        s->err = "number is out of range for a double";
        json_free(v);
        return NULL;
    }

    return v;
}


static json_value *
parse_value(jparse *s)
{
    json_value *v;

    skip_ws(s);

    if (s->p >= s->end) {
        s->err = "unexpected end of document";
        return NULL;
    }

    switch (*s->p) {

    case '{':
    case '[': {
        json_value *container;

        /* Bounded because the parser recurses and the document arrives from a
         * worker that may be in the middle of failing. A truncated or garbled
         * body should be a parse error, not a stack overflow in the harness
         * that was supposed to report it. */
        if (s->depth >= JSON_MAX_DEPTH) {
            s->err = "nesting too deep";
            return NULL;
        }

        s->depth++;
        container = (*s->p == '{') ? parse_object(s) : parse_array(s);
        s->depth--;

        return container;
    }

    case '"':
        v = value_new(JSON_STRING);
        if (v == NULL) {
            s->err = "out of memory";
            return NULL;
        }
        v->string = parse_string_raw(s);
        if (v->string == NULL) {
            json_free(v);
            return NULL;
        }
        return v;

    default:
        break;
    }

    if (literal(s, "true") || literal(s, "false")) {
        v = value_new(JSON_BOOL);
        if (v == NULL) {
            s->err = "out of memory";
            return NULL;
        }
        /* literal() already advanced; recover which one from the last char. */
        v->boolean = (s->p[-1] == 'e' && s->p[-2] == 'u') ? 1 : 0;
        return v;
    }

    if (literal(s, "null")) {
        return value_new(JSON_NULL);
    }

    return parse_number(s);
}


json_value *
json_parse(const char *text, const char **err)
{
    /* Length-delimited by strlen for callers that have a NUL-terminated string
     * and no separate length. A body that may carry an embedded NUL must use
     * json_parse_n instead: strlen would stop at the first NUL and this parser
     * would then accept whatever valid prefix preceded it while ignoring the
     * trailing bytes -- exactly the truncation json_parse_n exists to reject. */
    return json_parse_n(text, strlen(text), err);
}


json_value *
json_parse_n(const char *text, size_t len, const char **err)
{
    jparse      s;
    json_value *root;

    s.p = text;
    s.end = text + len;
    s.err = NULL;
    s.depth = 0;

    root = parse_value(&s);
    if (root == NULL) {
        if (err != NULL) {
            *err = s.err ? s.err : "parse failed";
        }
        return NULL;
    }

    skip_ws(&s);

    /* Trailing garbage is an error: it means the document was truncated and
     * re-sent, or two documents were concatenated. Either way the values we
     * would report are not the ones the caller thinks they are. */
    if (s.p != s.end) {
        if (err != NULL) {
            *err = "trailing garbage after document";
        }
        json_free(root);
        return NULL;
    }

    return root;
}


const json_value *
json_get(const json_value *root, const char *path)
{
    const json_value *cur = root;
    const char       *p = path;

    /*
     * Every segment must be non-empty, which rules out "", "zone.", ".zone"
     * and "zone..nodes".
     *
     * Without this, a trailing dot resolves to the PARENT: "zone." walks into
     * the zone object, finds no further segment, and returns it. A rule reading
     * `probe zone. == 1` would then be compared against an object and reported
     * as a type error -- close enough to look like a real failure, far enough
     * from the truth to send someone looking in the wrong place. A malformed
     * path is not a value.
     */
    if (*p == '\0') {
        return NULL;
    }

    while (*p != '\0') {
        const char *dot = strchr(p, '.');
        size_t      len = (dot != NULL) ? (size_t) (dot - p) : strlen(p);
        size_t      i;
        int         found = 0;

        if (len == 0) {
            return NULL;                    /* ".x", "x..y", or a trailing "." */
        }

        if (cur == NULL || cur->type != JSON_OBJECT) {
            return NULL;
        }

        for (i = 0; i < cur->count; i++) {
            if (strlen(cur->keys[i]) == len
                && memcmp(cur->keys[i], p, len) == 0)
            {
                cur = cur->items[i];
                found = 1;
                break;
            }
        }

        if (!found) {
            return NULL;
        }

        if (dot == NULL) {
            break;
        }

        p = dot + 1;

        /* The loop's own condition would end the walk here and hand back the
         * object we just descended into, so a trailing dot has to be caught
         * before the next iteration rather than by the empty-segment check
         * above -- that check only sees segments the loop re-enters for. */
        if (*p == '\0') {
            return NULL;
        }
    }

    return cur;
}


const char *
json_type_name(json_type t)
{
    switch (t) {
    case JSON_NULL:   return "null";
    case JSON_BOOL:   return "boolean";
    case JSON_NUMBER: return "number";
    case JSON_STRING: return "string";
    case JSON_OBJECT: return "object";
    case JSON_ARRAY:  return "array";
    }

    return "unknown";
}
