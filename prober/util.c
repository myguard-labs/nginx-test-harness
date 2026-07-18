/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * util.c -- see util.h.
 */

/* strdup() is POSIX, not C11, and the build asks for -std=c11 strictly. */
#define _GNU_SOURCE

#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


_Noreturn void
die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "prober: ");

    /* -Wformat=2 implies -Wformat-nonliteral, which fires on every va_list
     * forwarder because the format is a parameter rather than a literal. That
     * is the whole point of this function, so the diagnostic is suppressed for
     * exactly this line -- not the file. The checking is not lost: the
     * format(printf, 1, 2) attribute on the declaration in util.h moves it to
     * die()'s callers, where the literal actually is. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
    vfprintf(stderr, fmt, ap);
#pragma GCC diagnostic pop

    fprintf(stderr, "\n");
    va_end(ap);

    exit(2);
}


char *
xstrdup(const char *s)
{
    char *p = strdup(s);

    if (p == NULL) {
        die("out of memory");
    }

    return p;
}


char *
trim(char *s)
{
    char *end;

    while (*s != '\0' && isspace((unsigned char) *s)) {
        s++;
    }

    end = s + strlen(s);

    while (end > s && isspace((unsigned char) end[-1])) {
        end--;
    }

    *end = '\0';

    return s;
}


long
xstrtol(const char *s, const char *what)
{
    char *stop;
    long  v;

    if (s == NULL || *s == '\0') {
        die("%s: expected a number, got an empty value", what);
    }

    errno = 0;
    v = strtol(s, &stop, 10);

    /*
     * Three distinct failures, all of which atoi() would have reported as 0:
     * trailing garbage ("10junk"), a value outside long (ERANGE), and a token
     * that was not a number at all (stop == s, caught by the same check).
     */
    if (*stop != '\0') {
        die("%s: \"%s\" is not a number", what, s);
    }

    if (errno == ERANGE) {
        die("%s: \"%s\" is out of range", what, s);
    }

    return v;
}
