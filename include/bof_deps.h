/* bof_deps.h — BOF library dependency pre-validation and pre-loading.
 *
 * Before executing a BOF, nax_bof_execute / nax_async_start call
 * bof_deps_prepare() to ensure every LIBXXX$ symbol referenced by the
 * BOF has its backing shared library loaded in the current process.
 *
 * Policy:
 *   - Fail-fast: if any required library cannot be satisfied, the BOF
 *     is rejected before any code from it runs.
 *   - Silent on success: bof_deps_prepare() only writes to err_buf when
 *     it fails.
 *   - No whitelist: any DSO present in a standard system library
 *     directory is acceptable. User-writable paths (/tmp, /dev/shm,
 *     /home, /var/tmp, /root) are rejected.
 *   - Global switch: g_bof_deps_allow_dlopen controls whether missing
 *     libraries may be loaded via dlopen or whether the BOF must rely
 *     on what is already mapped.
 */

#ifndef BOF_DEPS_H
#define BOF_DEPS_H

#include <stdint.h>

/* Global policy switch.
 *
 *   0 -> strict mode: bof_deps_prepare only validates that every
 *        required library is already loaded. No dlopen is performed.
 *        Useful for OPSEC-sensitive environments where loading new
 *        DSOs would be visible to the kernel/EDR.
 *
 *   1 -> flexible mode (default): missing libraries are located in
 *        standard system paths and loaded via dlopen before the BOF
 *        runs.
 *
 * Set once at agent startup. Not thread-safe to flip at runtime. */
extern int g_bof_deps_allow_dlopen;

/* Return codes. */
#define BOF_DEPS_OK    0   /* every required library is loaded */
#define BOF_DEPS_FAIL -1   /* at least one required library is missing */

/* Pre-validate and (in flexible mode) pre-load all LIBXXX$ dependencies
 * declared by the BOF in elf_data / elf_size.
 *
 * Idempotent: calling it twice for the same BOF is safe and cheap
 * (second call finds everything already loaded and returns OK).
 *
 * On failure, writes a human-readable message into err_buf and returns
 * BOF_DEPS_FAIL. On success, err_buf is left untouched and BOF_DEPS_OK
 * is returned.
 *
 * Parameters:
 *   elf_data, elf_size : raw .o contents (same buffer passed to
 *                        nax_bof_execute).
 *   err_buf, err_sz    : error message buffer, may be NULL if the
 *                        caller does not want diagnostics.
 *
 * Returns BOF_DEPS_OK or BOF_DEPS_FAIL. */
int bof_deps_prepare(const uint8_t *elf_data, uint32_t elf_size,
                     char *err_buf, int err_sz);

#endif /* BOF_DEPS_H */
