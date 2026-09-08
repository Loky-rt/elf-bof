#include "bof_api.h"
#include <dlfcn.h>

void go(char *args, int args_len) {
    (void)args;
    (void)args_len;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] BOF with dlopen() initiated\n");

    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if (!handle) {
        BeaconPrintf(CALLBACK_ERROR, "[!] dlopen() failed: %s\n", dlerror());
        return;
    }

    void *func = dlsym(handle, "printf");
    if (func) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] dlsym() found printf\n");
    }

    dlclose(handle);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] BOF concluded\n");
}
