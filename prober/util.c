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
    vfprintf(stderr, fmt, ap);
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
