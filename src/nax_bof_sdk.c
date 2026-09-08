/* nax_bof_sdk.c — Linux BOF SDK core
 * Implements SDK initialization and the custom symbol registration API.
 * bof_resolve_symbol() in bof_api.c calls nax_bof_resolve_custom() here
 * before searching the base table.
 */

#include "nax_bof_sdk.h"

#include <string.h>
#include <stddef.h>
#include <pthread.h>

/* ── Custom symbol table ─────────────────────────────────────────────────── */

typedef struct {
    const char *name;
    void       *func;
} custom_sym_t;

static custom_sym_t     g_custom_syms[NAX_BOF_CUSTOM_SYMBOLS_MAX];
static int              g_custom_sym_count = 0;
static pthread_mutex_t  g_custom_syms_mu   = PTHREAD_MUTEX_INITIALIZER;

int nax_bof_register_symbol(const char *name, void *func) {
    if (!name || !func) return -1;
    pthread_mutex_lock(&g_custom_syms_mu);
    if (g_custom_sym_count >= NAX_BOF_CUSTOM_SYMBOLS_MAX) {
        pthread_mutex_unlock(&g_custom_syms_mu);
        return -1;
    }
    g_custom_syms[g_custom_sym_count].name = name;
    g_custom_syms[g_custom_sym_count].func = func;
    g_custom_sym_count++;
    pthread_mutex_unlock(&g_custom_syms_mu);
    return 0;
}

/* Called by bof_resolve_symbol() in bof_api.c before the base table lookup */
void *nax_bof_resolve_custom(const char *name) {
    pthread_mutex_lock(&g_custom_syms_mu);
    void *result = NULL;
    for (int i = 0; i < g_custom_sym_count; i++) {
        if (strcmp(name, g_custom_syms[i].name) == 0) {
            result = g_custom_syms[i].func;
            break;
        }
    }
    pthread_mutex_unlock(&g_custom_syms_mu);
    return result;
}

/* ── SDK init ────────────────────────────────────────────────────────────── */

void nax_bof_sdk_init(void) {
    nax_async_init();
    pthread_mutex_lock(&g_custom_syms_mu);
    memset(g_custom_syms, 0, sizeof(g_custom_syms));
    g_custom_sym_count = 0;
    pthread_mutex_unlock(&g_custom_syms_mu);
}
