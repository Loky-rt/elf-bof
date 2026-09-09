/* bof_deps.c — BOF library dependency pre-validation and pre-loading.
 *
 * See bof_deps.h for the policy contract.
 *
 * Layout of this file:
 *   - collect_hints_from_elf : parse .symtab, extract LIBXXX prefixes.
 *   - find_lib_on_disk       : resolve a hint to an absolute .so path.
 *   - dlopen_via_resolver    : call dlopen without going through dlsym.
 *   - load_lib_by_hint       : dlopen + register in the lib cache.
 *   - bof_deps_prepare       : public entry point.
 */

#define _GNU_SOURCE
#include "bof_deps.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>
#include <dirent.h>

#ifndef BOF_DEPS_ALLOW_DLOPEN
#define BOF_DEPS_ALLOW_DLOPEN 1
#endif

int g_bof_deps_allow_dlopen = BOF_DEPS_ALLOW_DLOPEN;


/* ── Hook into bof_api.c ─────────────────────────────────────────────────── */

/* Defined in bof_api.c. Returns 1 and writes *out_base if a DSO whose
 * short name (before the first '.' or '-') equals `hint` is already in
 * the runtime lib cache. Returns 0 otherwise. */
extern int  bof_lib_find(const char *hint, unsigned long *out_base);

/* Defined in bof_api.c. Re-scans /proc/self/maps and registers any DSO
 * not yet in the cache. Idempotent. Call after dlopen so the new lib
 * becomes resolvable by bof_resolve_symbol(). */
extern void bof_lib_rescan(void);

/* Defined in bof_api.c. Full symbol resolver (uses the same tables as
 * the ELF loader). Used here only to fetch dlopen without dlsym. */
extern void *bof_resolve_symbol(const char *name);

/* Defined in elf_bof.c. Walks the BOF's .symtab and fills `hints` with
 * the unique uppercase-normalised prefixes of undefined symbols that
 * contain '$'. Returns 0 on success, -1 on malformed ELF. */
extern int elf_bof_collect_deps(const uint8_t *elf, uint32_t sz,
                                char (*hints)[48], int max_hints,
                                int *out_count);

/* ── Tunables ────────────────────────────────────────────────────────────── */

/* Maximum number of unique library hints we track per BOF. Plenty for
 * any realistic BOF; a BOF with more than 64 distinct libraries is
 * pathological and can be rejected safely. */
#define BOF_DEPS_MAX_HINTS 64

/* Maximum length of a hint ("libcrypto", "libpthread", ...). */
#define BOF_DEPS_HINT_LEN  48

/* Maximum length of a resolved .so path. PATH_MAX is 4096 on Linux but
 * we cap lower: paths longer than this are rejected to avoid stack
 * abuse. */
#define BOF_DEPS_PATH_LEN  512

/* Directories searched when resolving a hint to a .so on disk.
 * Ordered by preference: multiarch first, then generic. The filter
 * bof_deps_path_is_acceptable() below is the real gatekeeper; this
 * list just narrows the search space. */
static const char *const g_lib_dirs[] = {
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/usr/lib64",
    "/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/lib64",
    "/usr/lib",
    "/lib",
    "/usr/local/lib",
    NULL
};

/* ── Global policy ───────────────────────────────────────────────────────── */

//int g_bof_deps_allow_dlopen = 1;   /* flexible by default */

/* ── Path filter ─────────────────────────────────────────────────────────── */

/* Accept only paths under standard system library directories.
 *
 * Rejected explicitly (defence in depth):
 *   /tmp/, /var/tmp/, /dev/shm/, /home/, /root/, /run/user/
 *   any path without a leading '/'
 *
 * Accepted: anything under /usr/lib, /usr/lib64, /lib, /lib64,
 * /usr/local/lib (including multiarch subdirs). */
static int bof_deps_path_is_acceptable(const char *p) {
    if (!p || p[0] != '/')                       return 0;
    if (strncmp(p, "/tmp/",          5) == 0)    return 0;
    if (strncmp(p, "/var/tmp/",      9) == 0)    return 0;
    if (strncmp(p, "/dev/shm/",      9) == 0)    return 0;
    if (strncmp(p, "/home/",         6) == 0)    return 0;
    if (strncmp(p, "/root/",         6) == 0)    return 0;
    if (strncmp(p, "/run/user/",    10) == 0)    return 0;
    if (strncmp(p, "/usr/lib/",      9) == 0)    return 1;
    if (strncmp(p, "/usr/lib64/",   10) == 0)    return 1;
    if (strncmp(p, "/lib/",          5) == 0)    return 1;
    if (strncmp(p, "/lib64/",        7) == 0)    return 1;
    if (strncmp(p, "/usr/local/lib/",15) == 0)   return 1;
    return 0;
}

/* ── Hint collection ─────────────────────────────────────────────────────── */

/* Thin wrapper around elf_bof_collect_deps so bof_deps.c does not need
 * to know the ELF layout. */
static int collect_hints(const uint8_t *elf, uint32_t sz,
                         char (*hints)[BOF_DEPS_HINT_LEN],
                         int max_hints, int *out_count) {
    return elf_bof_collect_deps(elf, sz, hints, max_hints, out_count);
}

/* ── Disk lookup ─────────────────────────────────────────────────────────── */

/* Match quality for a candidate filename. Higher is better.
 *
 * We score how closely a file in a system library directory matches the
 * requested hint, so that when several candidates exist (e.g. libpixman-1.so.0
 * and libpixman-1.so.0.46.4, which are typically symlinks one to the other)
 * we pick the one that glibc's ld.so would resolve via DT_SONAME.
 *
 * Score rubric:
 *   100  <hint>.so.<N>          exact, versioned soname (libz.so.1)
 *    90  <hint>.so              exact, unversioned (dev symlink)
 *    80  <hint>-<M>.so.<N>      hyphenated major version (libpixman-1.so.0)
 *    70  <hint>-<M>.so          hyphenated, unversioned
 *    50  <hint>*...so*          loose prefix match (last resort)
 *     0  no match
 *
 * The exact forms (100/90) are what we want; the hyphenated forms
 * (80/70) cover libraries whose soname embeds the major version
 * (libpixman-1.so.0, libgdk_pixbuf-2.0.so.0). The loose form (50) is a
 * safety net for exotic naming; it is only reached if nothing else
 * matched, and even then only if the file is a regular file whose name
 * ends in .so or .so.<digits>. */
static int score_candidate(const char *hint, const char *fname) {
    size_t hl = strlen(hint);
    if (strncmp(fname, hint, hl) != 0) return 0;

    const char *p = fname + hl;

    /* Skip an optional -<digits> segment. */
    int had_hyphen = 0;
    if (*p == '-') {
        const char *q = p + 1;
        if (*q < '0' || *q > '9') return 0;   /* not -<digits>, skip */
        while (*q >= '0' && *q <= '9') q++;
        /* Now *q should be '.' or '\0'. */
        if (*q != '.' && *q != '\0') return 0;
        p = q;
        had_hyphen = 1;
    }

    /* Now p should point at ".so" or at end of string. */
    if (strncmp(p, ".so", 3) != 0) return 0;
    p += 3;

    /* After ".so", either nothing, or ".<digits>", or ".<digits>.<digits>...". */
    int has_major = 0;
    int has_minor = 0;
    if (*p == '\0') {
        /* <hint>[ -N].so */
        return had_hyphen ? 70 : 90;
    }
    if (*p != '.') return 0;
    p++;
    if (*p < '0' || *p > '9') return 0;
    while (*p >= '0' && *p <= '9') p++;
    has_major = 1;
    if (*p == '\0') {
        /* <hint>[ -N].so.<N> */
        return had_hyphen ? 80 : 100;
    }
    if (*p != '.') return 0;
    p++;
    if (*p < '0' || *p > '9') return 0;
    while (*p >= '0' && *p <= '9') p++;
    has_minor = 1;
    if (*p == '\0' && has_major && has_minor) {
        /* <hint>[ -N].so.<N>.<N> — real file, not the preferred symlink,
         * but acceptable as a last resort. Score just below the
         * symlinked soname so we prefer it if nothing better exists. */
        return had_hyphen ? 60 : 65;
    }
    /* Anything past .so.<N>.<N> is too exotic; ignore. */
    return 0;
}

/* Scan a single directory for the best candidate matching hint.
 * Returns 1 and fills out_path if a match was found, 0 otherwise. */
static int scan_dir_for_hint(const char *dir, const char *hint,
                             char *out_path, size_t out_sz) {
    DIR *d = opendir(dir);
    if (!d) return 0;

    int   best_score = 0;
    char  best_name[BOF_DEPS_PATH_LEN] = {0};

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        /* Skip dotfiles and special entries. */
        if (de->d_name[0] == '.') continue;

        int score = score_candidate(hint, de->d_name);
        if (score <= best_score) continue;

        /* Build candidate path and verify it is a regular file. */
        char p[BOF_DEPS_PATH_LEN];
        int n = snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        if (n <= 0 || (size_t)n >= sizeof(p)) continue;
        if (!bof_deps_path_is_acceptable(p)) continue;

        struct stat st;
        if (stat(p, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        best_score = score;
        snprintf(best_name, sizeof(best_name), "%s", p);
    }

    closedir(d);

    if (best_score == 0) return 0;
    snprintf(out_path, out_sz, "%s", best_name);
    return 1;
}

/* Resolve a hint to an absolute .so path.
 *
 * Phase 1 (fast): try the canonical forms <dir>/<hint>.so.<N> for
 *                 N in {0..5} and <dir>/<hint>.so. This is a handful of
 *                 stat() calls and covers libz, libcrypto, libsqlite3,
 *                 libharfbuzz, etc.
 *
 * Phase 2 (thorough): if Phase 1 finds nothing, scan each system
 *                     directory with readdir and pick the highest-scoring
 *                     filename that starts with <hint>. This covers
 *                     libraries whose soname embeds a major version
 *                     separated by a hyphen: libpixman-1.so.0,
 *                     libgdk_pixbuf-2.0.so.0, etc. */
static int find_lib_on_disk(const char *hint,
                            char *out_path, size_t out_sz) {
    if (!hint || !out_path || out_sz == 0) return 0;

    /* Sanity: hint must not contain '/' or "..". */
    for (const char *q = hint; *q; q++) {
        if (*q == '/' || *q == '\\') return 0;
        if (q[0] == '.' && q[1] == '.') return 0;
    }

    /* ── Phase 1: exact match, no directory scan ── */

    char soname[BOF_DEPS_HINT_LEN + 8];
    int n = snprintf(soname, sizeof(soname), "%s.so", hint);
    if (n <= 0 || (size_t)n >= sizeof(soname)) return 0;

    for (int d = 0; g_lib_dirs[d]; d++) {
        /* <dir>/<hint>.so.<N> for N in {0..5} */
        for (int ver = 0; ver <= 5; ver++) {
            char p[BOF_DEPS_PATH_LEN];
            n = snprintf(p, sizeof(p), "%s/%s.%d",
                         g_lib_dirs[d], soname, ver);
            if (n <= 0 || (size_t)n >= sizeof(p)) continue;
            if (!bof_deps_path_is_acceptable(p)) continue;
            struct stat st;
            if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) {
                snprintf(out_path, out_sz, "%s", p);
                return 1;
            }
        }
        /* <dir>/<hint>.so */
        {
            char p[BOF_DEPS_PATH_LEN];
            n = snprintf(p, sizeof(p), "%s/%s", g_lib_dirs[d], soname);
            if (n <= 0 || (size_t)n >= sizeof(p)) continue;
            if (!bof_deps_path_is_acceptable(p)) continue;
            struct stat st;
            if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) {
                snprintf(out_path, out_sz, "%s", p);
                return 1;
            }
        }
    }

    /* ── Phase 2: directory scan, prefix match ── */

    for (int d = 0; g_lib_dirs[d]; d++) {
        if (scan_dir_for_hint(g_lib_dirs[d], hint, out_path, out_sz))
            return 1;
    }

    return 0;
}

/* ── dlopen without dlsym ────────────────────────────────────────────────── */

/* Fetch dlopen through the SDK's own resolver (LIBC$dlopen). The symbol
 * exists in libc on every glibc/musl system, so this never falls back
 * to dlsym. Using the resolver keeps the symbol name out of any
 * PLT/GOT entry visible to hooks that patch dlsym itself. */
static void *dlopen_via_resolver(const char *path) {
    typedef void *(*dlopen_fn)(const char *, int);
    dlopen_fn fn = (dlopen_fn)bof_resolve_symbol("LIBC$dlopen");
    if (!fn) return NULL;
    return fn(path, RTLD_LAZY | RTLD_LOCAL/*RTLD_GLOBAL*/);
}

/* ── Lib loading by hint ─────────────────────────────────────────────────── */

/* Ensure the library identified by `hint` is loaded in the process.
 *
 * Returns 1 on success (and writes *out_base with the runtime load
 * bias), 0 on failure.
 *
 * Steps:
 *   1. Ask bof_api.c whether the hint is already in the cache.
 *   2. In strict mode (g_bof_deps_allow_dlopen == 0), fail now.
 *   3. Locate the .so on disk.
 *   4. dlopen via the resolver.
 *   5. Force a re-scan of /proc/self/maps so the newly loaded DSO
 *      enters the cache and becomes resolvable by bof_resolve_symbol().
 *   6. Return the base.
 *
 * Idempotent: if the lib is already loaded, returns immediately. */
static int load_lib_by_hint(const char *hint, unsigned long *out_base) {
    if (out_base) *out_base = 0;

    /* 1. Already loaded? */
    unsigned long base = 0;
    if (bof_lib_find(hint, &base)) {
        if (out_base) *out_base = base;
        return 1;
    }

    /* 2. Strict mode: refuse to dlopen. */
    if (!g_bof_deps_allow_dlopen)
        return 0;

    /* 3. Locate on disk. */
    char path[BOF_DEPS_PATH_LEN];
    if (!find_lib_on_disk(hint, path, sizeof(path)))
        return 0;

    /* 4. dlopen. */
    if (!dlopen_via_resolver(path))
        return 0;

    /* 5. Register in the cache. */
    bof_lib_rescan();

    /* 6. Re-read the base from the cache. */
    if (bof_lib_find(hint, &base)) {
        if (out_base) *out_base = base;
        return 1;
    }
    /* dlopen succeeded but the cache does not see it: something is off
     * with the path filter or the DSO's ELF header. Treat as failure so
     * the BOF is rejected rather than crashing later. */
    return 0;
}

/* ── Public entry point ──────────────────────────────────────────────────── */

int bof_deps_prepare(const uint8_t *elf_data, uint32_t elf_size,
                     char *err_buf, int err_sz) {
    if (err_buf && err_sz > 0) err_buf[0] = '\0';

    if (!elf_data || elf_size == 0) {
        if (err_buf && err_sz > 0)
            snprintf(err_buf, err_sz, "BOF dependency check: empty ELF");
        return BOF_DEPS_FAIL;
    }

    /* 1. Collect hints from the BOF's .symtab. */
    char hints[BOF_DEPS_MAX_HINTS][BOF_DEPS_HINT_LEN];
    int  nhints = 0;
    if (collect_hints(elf_data, elf_size, hints, BOF_DEPS_MAX_HINTS,
                      &nhints) != 0) {
        if (err_buf && err_sz > 0)
            snprintf(err_buf, err_sz,
                     "BOF dependency check: could not parse ELF symbol table");
        return BOF_DEPS_FAIL;
    }

    /* 2. Validate that every hint can be satisfied. */
    for (int i = 0; i < nhints; i++) {
        unsigned long base = 0;
        if (bof_lib_find(hints[i], &base)) {
            continue;   /* already loaded, nothing to do */
        }

        if (!g_bof_deps_allow_dlopen) {
            if (err_buf && err_sz > 0)
                snprintf(err_buf, err_sz,
                         "BOF requires %s.so but strict mode forbids dlopen",
                         hints[i]);
            return BOF_DEPS_FAIL;
        }

        char path[BOF_DEPS_PATH_LEN];
        if (!find_lib_on_disk(hints[i], path, sizeof(path))) {
            if (err_buf && err_sz > 0)
                snprintf(err_buf, err_sz,
                         "BOF requires %s.so which is not loaded and "
                         "not present in any system library directory",
                         hints[i]);
            return BOF_DEPS_FAIL;
        }
        /* Not loaded but locatable: OK, will be loaded in step 3. */
    }

    /* 3. Pre-load everything that is missing.
     *    load_lib_by_hint() is idempotent: already-loaded libs are
     *    short-circuited, so this loop is cheap when called twice. */
    for (int i = 0; i < nhints; i++) {
        unsigned long base = 0;
        if (!load_lib_by_hint(hints[i], &base)) {
            if (err_buf && err_sz > 0)
                snprintf(err_buf, err_sz,
                         "BOF requires %s.so but loading it failed",
                         hints[i]);
            return BOF_DEPS_FAIL;
        }
    }

    return BOF_DEPS_OK;
}
