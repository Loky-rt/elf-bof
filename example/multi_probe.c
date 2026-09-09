#include "bof_api.h"

extern const char   *LIBZ$zlibVersion(void);
extern const char   *LIBSQLITE3$sqlite3_libversion(void);
extern int           LIBPIXMAN$pixman_version(void);   /* ← int, no const char * */
extern const char   *LIBHARFBUZZ$hb_version_string(void);
extern unsigned int  LIBPNG16$png_access_version_number(void);
extern const char   *LIBNSPR4$PR_GetVersion(void);
extern int           LIBCAIRO$cairo_version(void);

void go(char *args, int args_len) {
    (void)args; (void)args_len;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] multi-probe\n");

    if (LIBZ$zlibVersion)
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LIBZ        = %s\n", LIBZ$zlibVersion());
    if (LIBSQLITE3$sqlite3_libversion)
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LIBSQLITE3  = %s\n", LIBSQLITE3$sqlite3_libversion());
    if (LIBPIXMAN$pixman_version) {
        int v = LIBPIXMAN$pixman_version();
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LIBPIXMAN   = %d.%d.%d\n",
                     (v / 10000) % 100, (v / 100) % 100, v % 100);
    }
    if (LIBHARFBUZZ$hb_version_string)
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LIBHARFBUZZ = %s\n", LIBHARFBUZZ$hb_version_string());
    if (LIBPNG16$png_access_version_number)
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LIBPNG16    = %u\n",
                     (unsigned int)LIBPNG16$png_access_version_number());
    if (LIBNSPR4$PR_GetVersion)
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LIBNSPR4    = %s\n", LIBNSPR4$PR_GetVersion());
    if (LIBCAIRO$cairo_version) {
        int v = LIBCAIRO$cairo_version();
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LIBCAIRO    = %d.%d.%d\n",
                     (v / 10000) % 100, (v / 100) % 100, v % 100);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] done\n");
}
