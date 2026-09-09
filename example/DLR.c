#include "bof_api.h"

extern int    LIBC$getpid(void);
extern int    LIBC$getppid(void);
extern int    LIBC$getuid(void);
extern int    LIBC$geteuid(void);
extern int    LIBC$getgid(void);
extern char  *LIBC$getenv(const char *);
extern char  *LIBC$getcwd(char *, int);
extern int    LIBC$uname(void *);
extern long   LIBC$sysconf(int);
extern int    LIBC$access(const char *, int);
extern void  *LIBC$opendir(const char *);
extern void  *LIBC$readdir(void *);
extern int    LIBC$closedir(void *);
extern void  *LIBC$fopen(const char *, const char *);
extern char  *LIBC$fgets(char *, int, void *);
extern int    LIBC$fclose(void *);
extern double LIBC$strtod(const char *, char **);
extern long   LIBC$time(long *);

void go(char *args, int args_len) {
    (void)args;
    (void)args_len;
    BeaconPrintf(CALLBACK_OUTPUT, "PID=%d PPID=%d UID=%d EUID=%d GID=%d\n",
        LIBC$getpid(), LIBC$getppid(), LIBC$getuid(), LIBC$geteuid(), LIBC$getgid());
    char *home = LIBC$getenv("HOME");
    BeaconPrintf(CALLBACK_OUTPUT, "HOME=%s\n", home ? home : "(null)");
    char cwd[256];
    if (LIBC$getcwd(cwd, sizeof(cwd)))
        BeaconPrintf(CALLBACK_OUTPUT, "CWD=%s\n", cwd);
//    char uts[512];
    //AxMemset(uts, 0, 512);
    //char uts[512];
    //for (int i = 0; i < 512; i++) uts[i] = 0;
    char uts[512] = {0};
    if (LIBC$uname(uts) == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "Kernel: %s %s %s\n", uts, uts+130, uts+260);
    BeaconPrintf(CALLBACK_OUTPUT, "CPUs=%ld\n", LIBC$sysconf(84));
    int r = LIBC$access("/etc/passwd", 0);
    BeaconPrintf(CALLBACK_OUTPUT, "access=%d\n", r);
    void *dir = LIBC$opendir("/tmp");
    if (dir) {
        void *ent = LIBC$readdir(dir);
        if (ent) BeaconPrintf(CALLBACK_OUTPUT, "readdir OK\n");
        LIBC$closedir(dir);
    }
    void *f = LIBC$fopen("/etc/hostname", "r");
    if (f) {
        char buf[128];
        if (LIBC$fgets(buf, sizeof(buf), f))
            BeaconPrintf(CALLBACK_OUTPUT, "hostname: %s", buf);
        LIBC$fclose(f);
    }
    double pi = LIBC$strtod("3.14159", 0);
    BeaconPrintf(CALLBACK_OUTPUT, "strtod=%.5f\n", pi);
    long now = LIBC$time(0);
    BeaconPrintf(CALLBACK_OUTPUT, "time=%ld\n", now);
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== 19 LIBC$ OK ===\n");
}
