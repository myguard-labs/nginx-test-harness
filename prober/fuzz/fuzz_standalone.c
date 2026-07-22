/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Engine-neutral corpus-replay driver.
 *
 * libFuzzer (and honggfuzz, and AFL's persistent mode) supply their own main()
 * that calls LLVMFuzzerTestOneInput in a mutate loop. That loop needs clang and
 * runs unbounded, so it belongs in a scheduled discovery job, not on the PR
 * path. For the PR path we want the SAME targets replayed once over a fixed,
 * checked-in corpus under plain gcc + ASan/UBSan, with a nonzero exit on the
 * first crash -- deterministic, fast, no external engine.
 *
 * This file provides exactly that main(): each argv is a file (or a directory
 * of files) whose bytes are fed once to LLVMFuzzerTestOneInput. It is the LLVM
 * "StandaloneFuzzTargetMain" pattern. Linked with one fuzz_*.c at a time (each
 * defines LLVMFuzzerTestOneInput), it becomes a replay binary for that target.
 *
 * Exit status: 0 iff every input was processed without the process dying. A
 * sanitizer abort (ASan/UBSan halt_on_error) or a real crash terminates with a
 * nonzero status of the runtime's choosing -- which is the whole point, and is
 * what the ci.yml corpus-replay step asserts. A target that "reports but exits
 * 0" is the vacuous fuzz gate this driver is built to make impossible: there is
 * no reporting path here, only the process living or dying.
 */
/* S_ISLNK and lstat are POSIX, not C11; -std=c11 hides them without this. */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Optional one-time init some targets define; ours do not, so this stays a
 * weak-ish no-op via a local default. Kept for drop-in parity with libFuzzer
 * targets that use it. */
__attribute__((weak)) int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc;
    (void) argv;
    return 0;
}

static int
run_file(const char *path)
{
    FILE    *f;
    long     len;
    size_t   got;
    uint8_t *buf;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "fuzz-replay: cannot open %s\n", path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        fprintf(stderr, "fuzz-replay: cannot seek %s\n", path);
        return -1;
    }
    len = ftell(f);
    if (len < 0) {
        fclose(f);
        fprintf(stderr, "fuzz-replay: cannot tell %s\n", path);
        return -1;
    }
    rewind(f);

    /* An empty corpus file is legitimate (it is the size==0 edge case) and must
     * still reach the target, so a zero-length malloc is replaced with 1 to keep
     * the pointer non-NULL while the reported size stays 0. */
    buf = malloc((size_t) len == 0 ? 1 : (size_t) len);
    if (buf == NULL) {
        fclose(f);
        fprintf(stderr, "fuzz-replay: out of memory for %s\n", path);
        return -1;
    }

    got = fread(buf, 1, (size_t) len, f);
    fclose(f);
    if (got != (size_t) len) {
        free(buf);
        fprintf(stderr, "fuzz-replay: short read on %s\n", path);
        return -1;
    }

    LLVMFuzzerTestOneInput(buf, (size_t) len);
    free(buf);
    return 0;
}

static int
run_path(const char *path)
{
    struct stat  st;

    /* lstat, not stat: a symlink in the corpus (a -> ., or a -> /) would
     * otherwise be followed and, if it points at a directory, recurse forever.
     * A corpus is checked-in test data, so a symlink there is never a real
     * input -- skip it rather than chase it. */
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "fuzz-replay: cannot lstat %s\n", path);
        return -1;
    }

    if (S_ISLNK(st.st_mode)) {
        fprintf(stderr, "fuzz-replay: skipping symlink %s\n", path);
        return 0;
    }

    if (S_ISDIR(st.st_mode)) {
        DIR           *d;
        struct dirent *e;
        int            rc = 0;

        d = opendir(path);
        if (d == NULL) {
            fprintf(stderr, "fuzz-replay: cannot opendir %s\n", path);
            return -1;
        }
        while ((e = readdir(d)) != NULL) {
            char sub[4096];

            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
                continue;
            }
            if ((size_t) snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name)
                >= sizeof(sub))
            {
                fprintf(stderr, "fuzz-replay: path too long under %s\n", path);
                rc = -1;
                continue;
            }
            if (run_path(sub) != 0) {
                rc = -1;
            }
        }
        closedir(d);
        return rc;
    }

    return run_file(path);
}

int
main(int argc, char **argv)
{
    int  i;
    int  rc = 0;
    int  n = 0;

    LLVMFuzzerInitialize(&argc, &argv);

    if (argc < 2) {
        fprintf(stderr,
                "usage: %s <corpus-file-or-dir> [more ...]\n"
                "replays each input once through the fuzz target; a crash or a\n"
                "sanitizer abort terminates with a nonzero status.\n",
                argv[0]);
        return 2;
    }

    for (i = 1; i < argc; i++) {
        if (run_path(argv[i]) != 0) {
            rc = 1;   /* an I/O problem with the corpus, not a target crash */
        }
        n++;
    }

    fprintf(stderr, "fuzz-replay: %d path(s) processed clean\n", n);
    return rc;
}
