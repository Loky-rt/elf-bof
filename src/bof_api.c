/* bof_api.c — Linux Beacon API implementation for BOF execution
 * Provides the function table that the ELF BOF loader resolves against.
 */

#include "bof_api.h"
#include "elf_bof.h"

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/time.h>
#include <limits.h>

/* Syscall numbers for compatibility with older systems (Linux x86_64) */

#ifndef SYS_process_vm_readv
#define SYS_process_vm_readv   310
#endif

#ifndef SYS_process_vm_writev
#define SYS_process_vm_writev  311
#endif

#ifndef SYS_pidfd_open
#define SYS_pidfd_open         434
#endif

#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd        438
#endif

#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup     425
#endif

#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter     426
#endif

#ifndef SYS_io_uring_register
#define SYS_io_uring_register  427
#endif

/* ── Output buffer ── */

typedef struct { char *data; uint32_t len; uint32_t cap; } bof_buf_t;
static __thread bof_buf_t g_bof_output;
static __thread int g_bof_initialized = 0, g_bof_error = 0;

static void buf_ensure(bof_buf_t *b, uint32_t extra) {
    if (b->len + extra > b->cap) {
        uint32_t nc = (b->cap == 0) ? 4096 : b->cap;
        while (nc < b->len + extra) nc *= 2;
        if (nc > BOF_OUTPUT_MAX) nc = BOF_OUTPUT_MAX;
        char *p = (char *)realloc(b->data, nc);
        if (!p) return;
        b->data = p;
        b->cap = nc;
    }
}
static void buf_append(bof_buf_t *b, const void *d, uint32_t n) {
    buf_ensure(b, n);
    if (b->len + n <= b->cap) { memcpy(b->data + b->len, d, n); b->len += n; }
}

void bof_output_init(void) {
    if (!g_bof_initialized) { memset(&g_bof_output, 0, sizeof(g_bof_output)); g_bof_initialized = 1; }
    else g_bof_output.len = 0;
    g_bof_error = 0;
}
void bof_output_cleanup(void) {
    if (g_bof_initialized) { free(g_bof_output.data); memset(&g_bof_output, 0, sizeof(g_bof_output)); g_bof_initialized = 0; }
}
const char *bof_output_get(uint32_t *out_len) {
    if (!g_bof_initialized || g_bof_output.len == 0) { if (out_len) *out_len = 0; return ""; }
    buf_ensure(&g_bof_output, 1);
    if (g_bof_output.data) g_bof_output.data[g_bof_output.len] = '\0';
    if (out_len) *out_len = g_bof_output.len;
    return g_bof_output.data ? g_bof_output.data : "";
}
int bof_output_get_error(void) { return g_bof_error; }

static unsigned int swap32(unsigned int v) {
    return ((v>>24)&0xFF)|((v>>8)&0xFF00)|((v<<8)&0xFF0000)|((v<<24)&0xFF000000);
}

/* ── Beacon Data Parser ── */

void BeaconDataParse(datap *p, char *buf, int sz) {
    if (!p) return;
    if (!buf || sz < 4) {
        p->original = p->buffer = buf;
        p->length = p->size = 0;
        return;
    }
    p->original = buf;
    p->buffer   = buf + 4;
    p->length   = sz - 4;
    p->size     = sz - 4;
}
int BeaconDataInt(datap *p) {
    if(!p||p->length<4)return 0;
    int v=0; memcpy(&v,p->buffer,4);
    p->buffer+=4;
    p->length-=4;
    return v;
}
short BeaconDataShort(datap *p) {
    if(!p||p->length<2)return 0;
    short v=0;
    memcpy(&v,p->buffer,2);
    p->buffer+=2;
    p->length-=2;
    return v;
}
int BeaconDataLength(datap *p) { return p?p->length:0; }
char *BeaconDataExtract(datap *p, int *sz) {
    if (!p || p->length < 4) return NULL;
    unsigned int l = 0;
    memcpy(&l, p->buffer, 4);
    p->length -= 4;
    p->buffer += 4;
    if (l > (unsigned int)p->length) return NULL;
    char *o = p->buffer;
    p->buffer += (int)l;
    p->length -= (int)l;
    if (sz) *sz = (int)l;
    return o;
}

/* ── Beacon Output ── */

void BeaconOutput(int type, const char *data, int len) {
    if(!data||!g_bof_initialized)return;
    if(type==CALLBACK_ERROR)g_bof_error=CALLBACK_ERROR;
    buf_append(&g_bof_output, data, len>0?(uint32_t)len:(uint32_t)strlen(data));
}
void BeaconPrintf(int type, const char *fmt, ...) {
    if(!fmt||!g_bof_initialized)return;
    if(type==CALLBACK_ERROR)g_bof_error=CALLBACK_ERROR;
    va_list a; va_start(a,fmt); int n=vsnprintf(NULL,0,fmt,a); va_end(a);
    if(n<=0)return;
    char *t=(char*)malloc(n+1); if(!t)return;
    va_start(a,fmt); vsnprintf(t,n+1,fmt,a); va_end(a);
    buf_append(&g_bof_output,t,(uint32_t)n); free(t);
}

/* ── Beacon Format ── */

void BeaconFormatAlloc(formatp *f, int m) { if(!f)return; f->original=(char*)calloc(1,m); f->buffer=f->original; f->length=0; f->size=m; }
void BeaconFormatReset(formatp *f) { if(!f||!f->original)return; memset(f->original,0,f->size); f->buffer=f->original; f->length=0; }
void BeaconFormatAppend(formatp *f, const char *t, int l) { if(!f||!t||f->length+l>f->size)return; memcpy(f->buffer,t,l); f->buffer+=l; f->length+=l; }
void BeaconFormatPrintf(formatp *f, const char *fmt, ...) {
    if(!f||!fmt)return;
    int r=f->size-f->length;
    if(r<=0)return;
    va_list a; va_start(a,fmt); int w=vsnprintf(f->buffer,r,fmt,a); va_end(a);
    if(w>0){f->length+=w;f->buffer+=w;}
}
char *BeaconFormatToString(formatp *f, int *s) { if(!f)return NULL; if(s)*s=f->length; return f->original; }
void BeaconFormatFree(formatp *f) { if(!f)return; if(f->original){memset(f->original,0,f->size);free(f->original);} f->original=NULL;f->buffer=NULL;f->length=0;f->size=0; }
void BeaconFormatInt(formatp *f, int v) { if(!f||f->length+4>f->size)return; unsigned int o=swap32((unsigned int)v); memcpy(f->buffer,&o,4); f->length+=4; f->buffer+=4; }

int BeaconIsAdmin(void) { return (geteuid()==0)?1:0; }

/* ── File system ── */

int AxFstatvfs(int fd, struct statvfs *buf) {
    return fstatvfs(fd, buf);
}

int AxStatvfs(const char *path, struct statvfs *buf) {
    return statvfs(path, buf);
}

char *AxRealpath(const char *path, char *resolved_path) {
    if (!path) return NULL;
    return realpath(path, resolved_path);
}
int AxOpenFile(const char *p, int f, int m) { return p?open(p,f,m):-1; }
int AxCloseFile(int fd) { return fd>=0?close(fd):-1; }
int AxReadFile(int fd, void *b, int c) { return (fd>=0&&b&&c>0)?(int)read(fd,b,c):-1; }
int AxReadFileToBuffer(const char *path, char **out, int max) {
    if(!path||!out)return-1;
    if(max<=0)max=1048576;
    int fd=open(path,O_RDONLY); if(fd<0)return-1;
    char *b=(char*)malloc(max+1); if(!b){close(fd);return-1;}
    int t=0; while(t<max){int n=(int)read(fd,b+t,max-t);if(n<=0)break;t+=n;}
    close(fd); b[t]='\0'; *out=b; return t;
}
int AxFileStat(const char *p, unsigned int *m, long *s, unsigned int *u, unsigned int *g) {
    if(!p)return-1;
    struct stat st;
    if(stat(p,&st)!=0)return-1;
    if(m)*m=(unsigned int)st.st_mode;
    if(s)*s=(long)st.st_size;
    if(u)*u=(unsigned int)st.st_uid;
    if(g)*g=(unsigned int)st.st_gid;
    return 0;
}
int AxOpenDir(const char *p) { return p?open(p,O_RDONLY|O_DIRECTORY):-1; }
int AxReadDir(int fd, void *b, int s) { return(fd<0||!b||s<=0)?-1:(int)syscall(SYS_getdents64,fd,b,(unsigned int)s); }

/* ── Memory + Strings ── */

void *AxMalloc(int s) { return s>0?malloc(s):NULL; }
void  AxFree(void *p) { if(p)free(p); }
void *AxMemset(void *s, int c, int n) { return(s&&n>0)?memset(s,c,n):s; }
void *AxMemcpy(void *d, const void *s, int n) { return(d&&s&&n>0)?memcpy(d,s,n):d; }
int   AxStrlen(const char *s) { return s?(int)strlen(s):0; }
int   AxStrcmp(const char *a, const char *b) { return(a&&b)?strcmp(a,b):-1; }
int   AxStrncmp(const char *a, const char *b, int n) { return(a&&b&&n>0)?strncmp(a,b,n):-1; }
char *AxStrcpy(char *d, const char *s) { return(d&&s)?strcpy(d,s):d; }
char *AxStrncpy(char *d, const char *s, int n) { return(d&&s&&n>0)?strncpy(d,s,n):d; }
char *AxStrcat(char *d, const char *s) { return(d&&s)?strcat(d,s):d; }
char *AxStrstr(const char *h, const char *n) { return(h&&n)?(char*)strstr(h,n):NULL; }
char *AxStrchr(const char *s, int c) { return s?(char*)strchr(s,c):NULL; }
int AxSnprintf(char *b, int s, const char *f, ...) {
    if(!b||!f||s<=0)return 0;
    va_list a; va_start(a,f);
    int r=vsnprintf(b,s,f,a);
    va_end(a);
    return r;
}

/* ── Process info ── */

int AxGetPid(void) { return(int)getpid(); }
int AxGetUid(void) { return(int)getuid(); }
int AxGetEuid(void) { return(int)geteuid(); }
int AxGetCwd(char *b, int s) { return(!b||s<=0)?-1:(getcwd(b,s)?(int)strlen(b):-1); }
int AxGetEnv(const char *name, char *out, int out_size) {
    if(!name||!out||out_size<=0)return-1;
    char *d=NULL; int dl=AxReadFileToBuffer("/proc/self/environ",&d,65536);
    if(dl<=0||!d)return-1;
    int nl=(int)strlen(name);
    int found=-1;
    int p=0;
    while(p<dl){char *e=d+p;int el=0;while(p+el<dl&&e[el]!='\0')el++;
        if(el>nl+1&&strncmp(e,name,nl)==0&&e[nl]=='='){
            char *v=e+nl+1;int vl=el-nl-1;if(vl>=out_size)vl=out_size-1;
            memcpy(out,v,vl);out[vl]='\0';found=vl;break;}
        p+=el+1;}
    free(d); return found;
}

int AxFileTime(const char *path, long *atime, long *mtime) {
    if (!path) return -1;
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if (atime) *atime = (long)st.st_atime;
    if (mtime) *mtime = (long)st.st_mtime;
    return 0;
}
int AxSetFileTime(const char *path, long atime, long mtime) {
    if (!path) return -1;
    struct timespec ts[2];
    ts[0].tv_sec = atime; ts[0].tv_nsec = 0;
    ts[1].tv_sec = mtime; ts[1].tv_nsec = 0;
    return utimensat(AT_FDCWD, path, ts, 0);
}

/* ── Networking ── */

int AxSocket(int d, int t, int p) { return socket(d,t,p); }
int AxConnect(int fd, const void *a, int l) { return connect(fd,(const struct sockaddr*)a,(socklen_t)l); }
int AxBind(int fd, const void *a, int l) { return bind(fd,(const struct sockaddr*)a,(socklen_t)l); }
int AxListen(int fd, int b) { return listen(fd,b); }
int AxAccept(int fd, void *a, int *l) {
    socklen_t sl=l?(socklen_t)*l:0; int r=accept(fd,(struct sockaddr*)a,l?&sl:NULL); if(l)*l=(int)sl; return r;
}
int AxSend(int fd, const void *b, int l, int f) { return(int)send(fd,b,(size_t)l,f); }
int AxRecv(int fd, void *b, int l, int f) { return(int)recv(fd,b,(size_t)l,f); }
int AxSendto(int fd, const void *b, int l, int f, const void *da, int al) {
    return(int)sendto(fd,b,(size_t)l,f,(const struct sockaddr*)da,(socklen_t)al);
}
int AxRecvfrom(int fd, void *b, int l, int f, void *sa, int *al) {
    socklen_t sl=al?(socklen_t)*al:0;
    int r=(int)recvfrom(fd,b,(size_t)l,f,(struct sockaddr*)sa,al?&sl:NULL);
    if(al)*al=(int)sl;
    return r;
}
int AxClose(int fd) { return close(fd); }
int AxSetsockopt(int fd, int lv, int on, const void *ov, int ol) {
    return setsockopt(fd,lv,on,ov,(socklen_t)ol);
}
int AxGetsockopt(int fd, int lv, int on, void *ov, int *ol) {
    socklen_t sl=ol?(socklen_t)*ol:0;
    int r=getsockopt(fd,lv,on,ov,ol?&sl:NULL); if(ol)*ol=(int)sl; return r;
}

/* ── Address conversion ── */

int AxInetPton(int af, const char *s, void *d) { return inet_pton(af,s,d); }
const char *AxInetNtop(int af, const void *s, char *d, int sz) { return inet_ntop(af,s,d,(socklen_t)sz); }
char *AxInetNtoa(unsigned int a) { struct in_addr i; i.s_addr=a; return inet_ntoa(i); }
unsigned short AxHtons(unsigned short v) { return htons(v); }
unsigned short AxNtohs(unsigned short v) { return ntohs(v); }

/* ── System ── */

int AxGetErrno(void) { return errno; }
int AxFcntl(int fd, int cmd, int arg) { return fcntl(fd,cmd,arg); }
int AxPoll(void *fds, int n, int ms) { return poll((struct pollfd*)fds,(nfds_t)n,ms); }

/* ── Async support ── */

extern int nax_async_get_stop_fd(void);
int BeaconGetStopJobEvent(void) { return nax_async_get_stop_fd(); }

/* ── Inter-BOF shared globals ── */

#define MAX_GLOBALS 16
static struct { const char *key; void *ptr; } g_bof_globals[MAX_GLOBALS];
static int g_bof_nglobals = 0;
static pthread_mutex_t g_bof_globals_mu = PTHREAD_MUTEX_INITIALIZER;

void *AxGetGlobal(const char *key) {
    if (!key) return NULL;
    pthread_mutex_lock(&g_bof_globals_mu);
    void *result = NULL;
    for (int i = 0; i < g_bof_nglobals; i++) {
        if (strcmp(g_bof_globals[i].key, key) == 0) {
            result = g_bof_globals[i].ptr;
            break;
        }
    }
    pthread_mutex_unlock(&g_bof_globals_mu);
    return result;
}

void AxSetGlobal(const char *key, void *ptr) {
    if (!key) return;
    pthread_mutex_lock(&g_bof_globals_mu);
    for (int i = 0; i < g_bof_nglobals; i++) {
        if (strcmp(g_bof_globals[i].key, key) == 0) {
            g_bof_globals[i].ptr = ptr;
            pthread_mutex_unlock(&g_bof_globals_mu);
            return;
        }
    }
    if (g_bof_nglobals < MAX_GLOBALS) {
        /* key must be a string literal or have static lifetime —
         * we store the pointer directly to avoid heap allocation
         * (and the associated leak on repeated calls with distinct keys). */
        g_bof_globals[g_bof_nglobals].key = key;
        g_bof_globals[g_bof_nglobals].ptr = ptr;
        g_bof_nglobals++;
    }
    pthread_mutex_unlock(&g_bof_globals_mu);
}

/* ── Symbol resolution table ── */

typedef struct { const char *name; void *func; } bof_api_entry_t;

/* ── Process control ── */

int AxClone(int (*fn)(void *), void *child_stack, int flags, void *arg) {
#ifdef __NR_clone
    return syscall(__NR_clone, flags, child_stack, arg, NULL, NULL, NULL);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int AxExecveat(int dirfd, const char *pathname, char *const argv[],
               char *const envp[], int flags) {
#ifdef __NR_execveat
    return syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int AxSocketpair(int domain, int type, int protocol, int sv[2]) {
    return socketpair(domain, type, protocol, sv);
}

void AxExit(int status) {
    _exit(status);
}

int AxPipe(int fd[2]) {              /* ← NUEVO */
    return pipe(fd);
}

int AxMemfdCreate(const char *name, unsigned int flags) {
#ifdef SYS_memfd_create
    return syscall(SYS_memfd_create, name, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int AxFexecve(int fd, char *const argv[], char *const envp[]) {
    return fexecve(fd, argv, envp);
}

int AxFork(void) {
    return fork();
}

int AxExecve(const char *path, char *const argv[], char *const envp[]) {
    return execve(path, argv, envp);
}

int AxWaitpid(int pid, int *status, int options) {
    return waitpid(pid, status, options);
}

int AxKill(int pid, int sig) {
    return kill(pid, sig);
}

long AxPtrace(int request, int pid, void *addr, void *data) {
    return ptrace(request, pid, addr, data);
}

ssize_t AxProcessVmReadv(int pid, const struct iovec *local_iov,
                         unsigned long liovcnt,
                         const struct iovec *remote_iov,
                         unsigned long riovcnt, unsigned long flags) {
#ifdef SYS_process_vm_readv
    return syscall(SYS_process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

ssize_t AxProcessVmWritev(int pid, const struct iovec *local_iov,
                          unsigned long liovcnt,
                          const struct iovec *remote_iov,
                          unsigned long riovcnt, unsigned long flags) {
#ifdef SYS_process_vm_writev
    return syscall(SYS_process_vm_writev, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int AxPidfdOpen(int pid, unsigned int flags) {
#ifdef SYS_pidfd_open
    return syscall(SYS_pidfd_open, pid, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int AxPidfdGetfd(int pidfd, int targetfd, unsigned int flags) {
#ifdef SYS_pidfd_getfd
    return syscall(SYS_pidfd_getfd, pidfd, targetfd, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

/* ── Advanced filesystem ── */

int AxChdir(const char *path) {
    return chdir(path);
}

int AxFchdir(int fd) {
    return fchdir(fd);
}

int AxChmod(const char *path, mode_t mode) {
    return chmod(path, mode);
}

int AxFchmod(int fd, mode_t mode) {
    return fchmod(fd, mode);
}

int AxChown(const char *path, uid_t owner, gid_t group) {
    return chown(path, owner, group);
}

int AxFchown(int fd, uid_t owner, gid_t group) {
    return fchown(fd, owner, group);
}

int AxSymlink(const char *target, const char *linkpath) {
    return symlink(target, linkpath);
}

ssize_t AxReadlink(const char *path, char *buf, size_t bufsiz) {
    return readlink(path, buf, bufsiz);
}

int AxDup(int oldfd) {
    return dup(oldfd);
}

int AxDup2(int oldfd, int newfd) {
    return dup2(oldfd, newfd);
}

int AxIoctl(int fd, unsigned long request, ...) {
    va_list args;
    va_start(args, request);
    void *arg = va_arg(args, void *);
    va_end(args);
    return ioctl(fd, request, arg);
}

/* ── System info ── */

int AxSysinfo(struct sysinfo *info) {
    return sysinfo(info);
}

int AxUname(struct utsname *buf) {
    return uname(buf);
}

/* ── io_uring ── */

int AxIoUringSetup(unsigned int entries, struct io_uring_params *p) {
#ifdef SYS_io_uring_setup
    return syscall(SYS_io_uring_setup, entries, p);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int AxIoUringEnter(int fd, unsigned int to_submit,
                   unsigned int min_complete, unsigned int flags) {
#ifdef SYS_io_uring_enter
    return syscall(SYS_io_uring_enter, fd, to_submit, min_complete, flags, NULL, 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int AxIoUringRegister(int fd, unsigned int opcode, void *arg,
                      unsigned int nr_args) {
#ifdef SYS_io_uring_register
    return syscall(SYS_io_uring_register, fd, opcode, arg, nr_args);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int AxWriteFile(int fd, const void *buf, int count) {
    return write(fd, buf, count);
}

void *AxMemmove(void *d, const void *s, int n) {
    return (d && s && n > 0) ? memmove(d, s, n) : d;
}

int AxMemcmp(const void *s1, const void *s2, int n) {
    return (s1 && s2 && n > 0) ? memcmp(s1, s2, n) : 0;
}

/* ── Time ── */
struct tm *AxLocaltime(const time_t *timer) {
    return localtime(timer);
}



static bof_api_entry_t bof_api_table[] = {
    {"BeaconDataParse",      (void*)BeaconDataParse},
    {"BeaconDataInt",        (void*)BeaconDataInt},
    {"BeaconDataShort",      (void*)BeaconDataShort},
    {"BeaconDataLength",     (void*)BeaconDataLength},
    {"BeaconDataExtract",    (void*)BeaconDataExtract},
    {"BeaconOutput",         (void*)BeaconOutput},
    {"BeaconPrintf",         (void*)BeaconPrintf},
    {"BeaconFormatAlloc",    (void*)BeaconFormatAlloc},
    {"BeaconFormatReset",    (void*)BeaconFormatReset},
    {"BeaconFormatAppend",   (void*)BeaconFormatAppend},
    {"BeaconFormatPrintf",   (void*)BeaconFormatPrintf},
    {"BeaconFormatToString", (void*)BeaconFormatToString},
    {"BeaconFormatFree",     (void*)BeaconFormatFree},
    {"BeaconFormatInt",      (void*)BeaconFormatInt},
    {"BeaconIsAdmin",        (void*)BeaconIsAdmin},
    {"BeaconGetStopJobEvent", (void*)BeaconGetStopJobEvent},
    {"AxOpenFile",           (void*)AxOpenFile},
    {"AxStatvfs",            (void*)AxStatvfs},
    {"AxFstatvfs",           (void*)AxFstatvfs},
    {"AxRealpath",           (void*)AxRealpath},
    {"AxCloseFile",          (void*)AxCloseFile},
    {"AxReadFile",           (void*)AxReadFile},
    {"AxReadFileToBuffer",   (void*)AxReadFileToBuffer},
    {"AxFileStat",           (void*)AxFileStat},
    {"AxOpenDir",            (void*)AxOpenDir},
    {"AxReadDir",            (void*)AxReadDir},
    {"AxMalloc",             (void*)AxMalloc},
    {"AxFree",               (void*)AxFree},
    {"AxMemset",             (void*)AxMemset},
    {"AxMemcpy",             (void*)AxMemcpy},
    {"AxStrlen",             (void*)AxStrlen},
    {"AxStrcmp",             (void*)AxStrcmp},
    {"AxStrncmp",            (void*)AxStrncmp},
    {"AxStrcpy",             (void*)AxStrcpy},
    {"AxStrncpy",            (void*)AxStrncpy},
    {"AxStrcat",             (void*)AxStrcat},
    {"AxStrstr",             (void*)AxStrstr},
    {"AxStrchr",             (void*)AxStrchr},
    {"AxSnprintf",           (void*)AxSnprintf},
    {"AxGetPid",             (void*)AxGetPid},
    {"AxGetUid",             (void*)AxGetUid},
    {"AxGetEuid",            (void*)AxGetEuid},
    {"AxGetCwd",             (void*)AxGetCwd},
    {"AxGetEnv",             (void*)AxGetEnv},
    {"AxFileTime",            (void*)AxFileTime},
    {"AxSetFileTime",         (void*)AxSetFileTime},
    {"AxSocket",             (void*)AxSocket},
    {"AxConnect",            (void*)AxConnect},
    {"AxBind",               (void*)AxBind},
    {"AxListen",             (void*)AxListen},
    {"AxAccept",             (void*)AxAccept},
    {"AxSend",               (void*)AxSend},
    {"AxRecv",               (void*)AxRecv},
    {"AxSendto",             (void*)AxSendto},
    {"AxRecvfrom",           (void*)AxRecvfrom},
    {"AxClose",              (void*)AxClose},
    {"AxSetsockopt",         (void*)AxSetsockopt},
    {"AxGetsockopt",         (void*)AxGetsockopt},
    {"AxInetPton",           (void*)AxInetPton},
    {"AxInetNtop",           (void*)AxInetNtop},
    {"AxInetNtoa",           (void*)AxInetNtoa},
    {"AxHtons",              (void*)AxHtons},
    {"AxNtohs",              (void*)AxNtohs},
    {"AxGetErrno",           (void*)AxGetErrno},
    {"AxFcntl",              (void*)AxFcntl},
    {"AxPoll",               (void*)AxPoll},
    {"AxExit",               (void*)AxExit},
    {"AxFork",               (void*)AxFork},
    {"AxClone",              (void*)AxClone},
    {"AxExecveat",           (void*)AxExecveat},
    {"AxSocketpair",         (void*)AxSocketpair},
    {"AxPipe",               (void*)AxPipe},
    {"AxMemfdCreate",        (void*)AxMemfdCreate},
    {"AxFexecve",            (void*)AxFexecve},
    {"AxExecve",             (void*)AxExecve},
    {"AxWaitpid",            (void*)AxWaitpid},
    {"AxKill",               (void*)AxKill},
    {"AxPtrace",             (void*)AxPtrace},
    {"AxProcessVmReadv",     (void*)AxProcessVmReadv},
    {"AxProcessVmWritev",    (void*)AxProcessVmWritev},
    {"AxPidfdOpen",          (void*)AxPidfdOpen},
    {"AxPidfdGetfd",         (void*)AxPidfdGetfd},
    /* Advanced filesystem */
    {"AxChdir",              (void*)AxChdir},
    {"AxFchdir",             (void*)AxFchdir},
    {"AxChmod",              (void*)AxChmod},
    {"AxFchmod",             (void*)AxFchmod},
    {"AxChown",              (void*)AxChown},
    {"AxFchown",             (void*)AxFchown},
    {"AxSymlink",            (void*)AxSymlink},
    {"AxReadlink",           (void*)AxReadlink},
    {"AxDup",                (void*)AxDup},
    {"AxDup2",               (void*)AxDup2},
    {"AxIoctl",              (void*)AxIoctl},
    /* System info */
    {"AxSysinfo",            (void*)AxSysinfo},
    {"AxUname",              (void*)AxUname},
    /* io_uring */
    {"AxIoUringSetup",       (void*)AxIoUringSetup},
    {"AxIoUringEnter",       (void*)AxIoUringEnter},
    {"AxIoUringRegister",    (void*)AxIoUringRegister},
    {"AxGetGlobal",          (void*)AxGetGlobal},
    {"AxSetGlobal",          (void*)AxSetGlobal},
    {"AxWriteFile",          (void*)AxWriteFile},
    /* MAPPING OF LIBC FUNCTIONS FOR ARM64 */
    {"memset",               (void*)AxMemset},
    {"memcpy",               (void*)AxMemcpy},
    {"memcmp",               (void*)AxMemcmp},
    {"memmove",              (void*)AxMemmove},
    {"strlen",               (void*)AxStrlen},
    {"strcmp",               (void*)AxStrcmp},
    {"strncmp",              (void*)AxStrncmp},
    {"strcpy",               (void*)AxStrcpy},
    {"strncpy",              (void*)AxStrncpy},
    {"strcat",               (void*)AxStrcat},
    {"strstr",               (void*)AxStrstr},
    {"strchr",               (void*)AxStrchr},
    {"snprintf",             (void*)AxSnprintf},
    {"vsnprintf",            (void*)vsnprintf},
    /* new */
    {"AxLocaltime",          (void*)AxLocaltime},
    {NULL, NULL}
};


/* ── Runtime symbol resolver — resolves LIBC$/RTLD$ prefixed symbols ─────
 * without dlsym. Parses /proc/self/maps to find libc base, then walks
 * the ELF .gnu_hash table in-memory to resolve by hash.
 *
 * OPSEC: No dlsym call, no string comparison in the search loop (hash only).
 * The requested function name exists briefly in the BOF's .rodata but never
 * passes through any hooked API. */

/* DJB2 hash — same algorithm used to query .gnu_hash */
static unsigned int _djb2(const char *s) {
    unsigned int h = 5381;
    while (*s) h = h * 33 + (unsigned char)*s++;
    return h;
}

/* Find libc base address from /proc/self/maps.
 * We look for the FIRST mapping of libc with file offset 00000000 — that's
 * the ELF base where headers start. The r-xp mapping has a non-zero offset
 * and would produce a wrong base. */
static void *_find_libc_base(void) {
    static void *cached_base = NULL;
    if (cached_base) return cached_base;

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return NULL;

    /* Read in chunks — /proc/self/maps can exceed 4KB for complex processes */
    char buf[256]; /* line buffer */
    char line[512];
    int line_len = 0;
    int n;

    while ((n = (int)read(fd, buf, sizeof(buf))) > 0) {
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\n' || line_len >= (int)sizeof(line) - 1) {
                line[line_len] = '\0';

                /* Match: contains "libc" AND has file offset 00000000 */
                if ((strstr(line, "libc.so") || strstr(line, "libc-")) &&
                    strstr(line, " 00000000 ")) {
                    /* Parse base address: "7f1234560000-..." */
                    unsigned long addr = 0;
                    char *p = line;
                    while (*p && *p != '-') {
                        unsigned int digit;
                        if (*p >= '0' && *p <= '9') digit = *p - '0';
                        else if (*p >= 'a' && *p <= 'f') digit = *p - 'a' + 10;
                        else break;
                        addr = (addr << 4) | digit;
                        p++;
                    }
                    close(fd);
                    cached_base = (void *)addr;
                    return cached_base;
                }
                line_len = 0;
            } else {
                line[line_len++] = buf[i];
            }
        }
    }
    close(fd);
    return NULL;
}

/* Resolve a symbol from libc's in-memory ELF structures using .gnu_hash */
static void *_resolve_from_libc(const char *name) {
    unsigned char *base = (unsigned char *)_find_libc_base();
    if (!base) return NULL;

    /* Validate ELF magic */
    if (base[0] != 0x7f || base[1] != 'E' || base[2] != 'L' || base[3] != 'F')
        return NULL;

    typedef struct { unsigned char e_ident[16]; uint16_t e_type, e_machine;
        uint32_t e_version; uint64_t e_entry, e_phoff, e_shoff;
        uint32_t e_flags; uint16_t e_ehsize, e_phentsize, e_phnum;
        uint16_t e_shentsize, e_shnum, e_shstrndx; } Ehdr64;

    typedef struct { uint32_t p_type, p_flags; uint64_t p_offset, p_vaddr,
        p_paddr, p_filesz, p_memsz, p_align; } Phdr64;

    typedef struct { uint64_t d_tag; union { uint64_t d_val; uint64_t d_ptr; } d_un; } Dyn64;

    typedef struct { uint32_t st_name; unsigned char st_info, st_other;
        uint16_t st_shndx; uint64_t st_value, st_size; } Sym64;

    Ehdr64 *eh = (Ehdr64 *)base;
    Phdr64 *phdrs = (Phdr64 *)(base + eh->e_phoff);

    /* Find PT_DYNAMIC */
    Dyn64 *dyn = NULL;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type == 2 /* PT_DYNAMIC */) {
            /* p_vaddr for in-memory access (already mapped), not p_offset (file) */
            dyn = (Dyn64 *)(base + phdrs[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return NULL;

    /* Extract .dynsym, .dynstr, .gnu_hash from PT_DYNAMIC.
     * On modern glibc (2.32+) these are ABSOLUTE virtual addresses.
     * On older systems they may be offsets from base. Detect by checking
     * if the pointer falls within a reasonable range of base. */
    uint64_t raw_symtab = 0, raw_strtab = 0, raw_gnu_hash = 0;

    for (Dyn64 *d = dyn; d->d_tag != 0; d++) {
        switch (d->d_tag) {
        case 6:  /* DT_SYMTAB */   raw_symtab   = d->d_un.d_ptr; break;
        case 5:  /* DT_STRTAB */   raw_strtab   = d->d_un.d_ptr; break;
        case 0x6ffffef5: /* DT_GNU_HASH */ raw_gnu_hash = d->d_un.d_ptr; break;
        }
    }
    if (!raw_symtab || !raw_strtab || !raw_gnu_hash) return NULL;

    /* If d_ptr is already > base, it's absolute. Otherwise add base. */
    uint64_t b = (uint64_t)base;
    Sym64      *symtab   = (Sym64 *)(raw_symtab   >= b ? raw_symtab   : b + raw_symtab);
    const char *strtab   = (const char *)(raw_strtab >= b ? raw_strtab : b + raw_strtab);
    uint32_t   *gnu_hash = (uint32_t *)(raw_gnu_hash >= b ? raw_gnu_hash : b + raw_gnu_hash);
    if (!symtab || !strtab || !gnu_hash) return NULL;

    /* GNU hash lookup */
    uint32_t nbuckets    = gnu_hash[0];
    uint32_t symoffset   = gnu_hash[1];
    uint32_t bloom_size  = gnu_hash[2];
    uint32_t bloom_shift = gnu_hash[3];
    uint64_t *bloom      = (uint64_t *)(gnu_hash + 4);
    uint32_t *buckets    = (uint32_t *)(bloom + bloom_size);
    uint32_t *chain      = buckets + nbuckets;

    uint32_t h = _djb2(name);

    /* Bloom filter check */
    uint64_t word = bloom[(h / 64) % bloom_size];
    uint64_t mask = (1ULL << (h % 64)) | (1ULL << ((h >> bloom_shift) % 64));
    if ((word & mask) != mask) return NULL;

    /* Bucket lookup */
    uint32_t idx = buckets[h % nbuckets];
    if (!idx) return NULL;

    /* Chain walk — compare hashes, verify with strcmp only on match */
    for (;; idx++) {
        uint32_t hh = chain[idx - symoffset];
        if ((hh | 1) == (h | 1)) {
            Sym64 *sym = &symtab[idx];
            if (sym->st_value && strcmp(strtab + sym->st_name, name) == 0) {
                /* st_value: if < base it's an offset, otherwise absolute */
                uint64_t sv = (uint64_t)sym->st_value;
                return (void *)(sv >= b ? sv : b + sv);
            }
        }
        if (hh & 1) break; /* end of chain */
    }
    return NULL;
}

/* Forward declaration — implemented in nax_bof_sdk.c */
void *nax_bof_resolve_custom(const char *name);

void *bof_resolve_symbol(const char *name) {
    if (!name) return NULL;

    /* Layer 1: Custom symbols registered by the agent via nax_bof_register_symbol() */
    void *custom = nax_bof_resolve_custom(name);
    if (custom) return custom;

    /* Layer 2: Base SDK table (Beacon* and Ax* APIs) */
    for (int i = 0; bof_api_table[i].name; i++)
        if (strcmp(name, bof_api_table[i].name) == 0)
            return bof_api_table[i].func;

    /* Layer 3: Runtime resolution from host libc via in-memory ELF parsing.
     * Activated by LIBC$ or RTLD$ prefix in the BOF symbol name.
     *
     *   extern void *LIBC$opendir(const char *);
     *   extern int   LIBC$closedir(void *);
     *
     * No dlsym, no -ldl dependency. Parses libc's .gnu_hash directly in RAM.
     *
     * OPSEC: The function name appears only in the BOF's .rodata and briefly
     * on the stack during hash comparison. No hooked API is called. */
    const char *real_name = NULL;
    if (strncmp(name, "LIBC$", 5) == 0)
        real_name = name + 5;
    else if (strncmp(name, "RTLD$", 5) == 0)
        real_name = name + 5;

    if (real_name) {
        void *addr = _resolve_from_libc(real_name);
        if (!addr)
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Runtime resolve failed: '%s' not found in host libc\n", real_name);
        return addr;
    }

    return NULL;
}
