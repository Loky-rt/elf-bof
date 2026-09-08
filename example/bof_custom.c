#include "bof_api.h"

extern int custom_add(int a, int b);
extern char *custom_get_info(void);

void go(char *args, int args_len) {
    (void)args;
    (void)args_len;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Custom BOF initiated\n");

    int resultado = custom_add(10, 32);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] 10 + 32 = %d\n", resultado);

    char *info = custom_get_info();
    BeaconPrintf(CALLBACK_OUTPUT, "[+] System info:: %s\n", info);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Custom BOF completed\n");
}
