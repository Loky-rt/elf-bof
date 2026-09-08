#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>
#include <pthread.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "nax_bof_sdk.h"

#define MAX_LINE 4096
#define MAX_ARGS 64
#define MAX_JOBS 8

#define C_RESET  "\033[0m"
#define C_BOLD   "\033[1m"
#define C_RED    "\033[31m"
#define C_GRN    "\033[32m"
#define C_YEL    "\033[33m"
#define C_CYN    "\033[36m"
#define C_WHT    "\033[37m"
#define C_DIM    "\033[2m"

static int g_color = 1;
static int g_running = 1;
static int g_has_async_jobs = 0;
static pthread_mutex_t g_async_mutex = PTHREAD_MUTEX_INITIALIZER;

/*────────────────────────────────────Custom functions for BOFs Example────────────────────────────────────────────────────────────────────*/
int custom_add(int a, int b) {
    return a + b;
}

char *custom_get_info(void) {
    static char info[256];
    snprintf(info, sizeof(info), "PID: %d, UID: %d", getpid(), getuid());
    return info;
}

/* ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── */

/* ── Timestamp ── */
static void ts(char *buf, size_t sz) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    struct tm *tm = localtime(&t.tv_sec);
    snprintf(buf, sz, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
}

#define LOG_INFO(fmt, ...) do { char _ts[16]; ts(_ts, sizeof(_ts)); \
    fprintf(stderr, "%s[%s %s]%s " fmt "\n", g_color ? C_CYN : "", _ts, "INF", g_color ? C_RESET : "", ##__VA_ARGS__); } while(0)
#define LOG_OK(fmt, ...) do { char _ts[16]; ts(_ts, sizeof(_ts)); \
    fprintf(stderr, "%s[%s %s]%s " fmt "\n", g_color ? C_GRN : "", _ts, "OK ", g_color ? C_RESET : "", ##__VA_ARGS__); } while(0)
#define LOG_ERR(fmt, ...) do { char _ts[16]; ts(_ts, sizeof(_ts)); \
    fprintf(stderr, "%s[%s %s]%s " fmt "\n", g_color ? C_RED : "", _ts, "ERR", g_color ? C_RESET : "", ##__VA_ARGS__); } while(0)

static void show_prompt(void) {
    printf("%s> %s", g_color ? C_GRN : "", g_color ? C_RESET : "");
    fflush(stdout);
}

static void print_output(const char *output, uint32_t len) {
    if (!output || len == 0) return;
    const char *bar = "─────────────────────────────────────────────────────────";

    fprintf(stdout, "\n%s BOF OUTPUT %s\n", g_color ? C_BOLD : "", bar);
    fwrite(output, 1, len, stdout);
    if (len > 0 && output[len-1] != '\n') fprintf(stdout, "\n");
    fprintf(stdout, "%s\n", bar);
    fflush(stdout);
}

static void async_callback(uint32_t task_id, uint8_t status,
                           const char *output, uint32_t output_len,
                           void *user_data) {
    (void)user_data;

    LOG_OK("Job #%u completed", task_id);

    if (output && output_len > 0) {
        print_output(output, output_len);
    }

    show_prompt();
}

static void *drain_thread(void *arg) {
    (void)arg;
    int idle_cycles = 0;
    const int MAX_IDLE = 10;

    while (g_running) {

        char buf[64];
        nax_async_list(buf, sizeof(buf));

        pthread_mutex_lock(&g_async_mutex);
        int has_jobs = (strstr(buf, "(no active jobs)") == NULL);
        g_has_async_jobs = has_jobs;
        pthread_mutex_unlock(&g_async_mutex);

        if (!has_jobs) {
            idle_cycles++;

            if (idle_cycles >= MAX_IDLE) {

                pthread_mutex_lock(&g_async_mutex);
                g_has_async_jobs = 0;
                pthread_mutex_unlock(&g_async_mutex);
                return NULL;
            }
            struct timespec sl = {0, 100000000};
            nanosleep(&sl, NULL);
            continue;
        }

        idle_cycles = 0;

        struct timespec sl = {0, 100000000};
        nanosleep(&sl, NULL);

        if (!g_running) break;

        struct { int flag; } ctx = {0};
        void cb(uint32_t tid, uint8_t status, const char *out, uint32_t olen, void *ud) {
            struct { int flag; } *c = ud;
            async_callback(tid, status, out, olen, NULL);
            c->flag = 1;
        }
        nax_async_drain(cb, &ctx);
    }

    return NULL;
}

static void update_drain_thread(void) {
    char buf[64];
    nax_async_list(buf, sizeof(buf));

    pthread_mutex_lock(&g_async_mutex);
    int has_jobs = (strstr(buf, "(no active jobs)") == NULL);
    int was_running = g_has_async_jobs;
    g_has_async_jobs = has_jobs;
    pthread_mutex_unlock(&g_async_mutex);

    if (has_jobs && !was_running) {
        LOG_INFO("Starting drain thread (async jobs active)");
        pthread_t tid;
        pthread_create(&tid, NULL, drain_thread, NULL);
        pthread_detach(tid);
    }
}

typedef struct { uint8_t *data; uint32_t len; uint32_t cap; } packer_t;

static void pack_ensure(packer_t *p, uint32_t extra) {
    if (p->len + extra > p->cap) {
        uint32_t nc = p->cap ? p->cap * 2 : 256;
        while (nc < p->len + extra) nc *= 2;
        p->data = realloc(p->data, nc);
        p->cap = nc;
    }
}

static void pack_u32le(packer_t *p, uint32_t v) {
    pack_ensure(p, 4);
    p->data[p->len++] = v & 0xFF;
    p->data[p->len++] = (v >> 8) & 0xFF;
    p->data[p->len++] = (v >> 16) & 0xFF;
    p->data[p->len++] = (v >> 24) & 0xFF;
}

static void pack_bytes(packer_t *p, const uint8_t *b, uint32_t n) {
    pack_ensure(p, n);
    memcpy(p->data + p->len, b, n);
    p->len += n;
}

static void pack_str(packer_t *p, const char *s) {
    uint32_t l = (uint32_t)strlen(s) + 1;
    pack_u32le(p, l);
    pack_bytes(p, (const uint8_t *)s, l);
}

static void pack_int(packer_t *p, int32_t v) {
    pack_u32le(p, (uint32_t)v);
}

static void pack_short(packer_t *p, int16_t v) {
    pack_u32le(p, (uint32_t)v);
}

static void pack_wstr(packer_t *p, const char *s) {
    size_t n = strlen(s);
    uint32_t blen = (uint32_t)(n + 1) * 2;
    pack_u32le(p, blen);
    pack_ensure(p, blen);
    for (size_t j = 0; j <= n; j++) {
        p->data[p->len++] = (uint8_t)s[j];
        p->data[p->len++] = 0x00;
    }
}

static uint8_t *build_args(char **argv, int argc, uint32_t *out_len) {
    if (argc == 0) { *out_len = 0; return NULL; }
    packer_t payload = {0};

    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        const char *colon = strchr(arg, ':');
        const char *type = "str";
        const char *value = arg;
        char type_buf[16] = "str";

        if (colon) {
            size_t tlen = (size_t)(colon - arg);
            if (tlen < sizeof(type_buf)) {
                memcpy(type_buf, arg, tlen);
                type_buf[tlen] = '\0';
                type = type_buf;
                value = colon + 1;
            }
        }

        if (strcmp(type, "str") == 0) {
            pack_str(&payload, value);
        } else if (strcmp(type, "int") == 0) {
            pack_int(&payload, (int32_t)strtol(value, NULL, 0));
        } else if (strcmp(type, "short") == 0) {
            pack_short(&payload, (int16_t)strtol(value, NULL, 0));
        } else if (strcmp(type, "wstr") == 0) {
            pack_wstr(&payload, value);
        } else {
            fprintf(stderr, "[!] Unknown arg type: %s\n", type);
            free(payload.data);
            return NULL;
        }
    }

    packer_t full = {0};
    pack_u32le(&full, payload.len);
    pack_bytes(&full, payload.data, payload.len);
    free(payload.data);
    *out_len = full.len;
    return full.data;
}

/* ── Load BOF ── */
static uint8_t *load_bof(const char *path, uint32_t *out_size) {
    struct stat st;
    if (stat(path, &st) != 0) {
        LOG_ERR("File not found: %s", path);
        return NULL;
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERR("Cannot open: %s", path);
        return NULL;
    }
    uint8_t *buf = malloc((size_t)st.st_size);
    if (!buf) { fclose(f); return NULL; }
    if ((uint32_t)fread(buf, 1, (size_t)st.st_size, f) != (uint32_t)st.st_size) {
        LOG_ERR("Read error: %s", path);
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *out_size = (uint32_t)st.st_size;
    return buf;
}

// Command: jobs
static void cmd_jobs(void) {
    char buf[512];
    nax_async_list(buf, sizeof(buf));
    fprintf(stdout, "\n%s", buf);
    show_prompt();
}

// Command: kill
static void cmd_kill(char *arg) {
    if (!arg) {
        LOG_ERR("Usage: kill <job_id>");
        show_prompt();
        return;
    }
    int job_id = atoi(arg);
    if (nax_async_kill(job_id) != 0) {
        LOG_ERR("Failed to kill job #%d", job_id);
    } else {
        LOG_OK("Kill signal sent to job #%d", job_id);
    }
    update_drain_thread();
    show_prompt();
}

static void execute_bof(char **args, int nargs) {
    if (nargs < 1) {
        LOG_ERR("No BOF file specified");
        show_prompt();
        return;
    }

    int async = 0;
    int arg_start = 0;
    if (strcmp(args[0], "--async") == 0) {
        async = 1;
        arg_start = 1;
    }

    const char *bof_path = args[arg_start];
    if (!bof_path) {
        LOG_ERR("No BOF file specified");
        show_prompt();
        return;
    }

    uint32_t bof_size = 0;
    uint8_t *bof_data = load_bof(bof_path, &bof_size);
    if (!bof_data) {
        show_prompt();
        return;
    }

    int n_bof_args = nargs - arg_start - 1;
    char **bof_args = (n_bof_args > 0) ? &args[arg_start + 1] : NULL;

    uint32_t args_len = 0;
    uint8_t *args_data = build_args(bof_args, n_bof_args, &args_len);

    if (async) {
        static uint32_t task_id = 1;
        int job_id = nax_async_start(task_id++, bof_data, bof_size, args_data, args_len);
        if (job_id < 0) {
            LOG_ERR("Failed to start async job");
        } else {
            LOG_OK("Job #%d started (task_id=%u) %s", job_id, task_id - 1, bof_path);

            update_drain_thread();
        }
        show_prompt();
    } else {
        char *output = NULL;
        uint32_t output_len = 0;
        int rc = nax_bof_execute(bof_data, bof_size, args_data, args_len,
                                 "go", &output, &output_len);
        if (rc == 0) {
            LOG_OK("BOF completed");
        } else {
            LOG_ERR("BOF failed");
        }

        if (output && output_len > 0) {
            print_output(output, output_len);
        }
        free(output);
        show_prompt();
    }

    free(bof_data);
    free(args_data);
}

static char *read_line(void) {
    static char buffer[MAX_LINE];
    char *result = fgets(buffer, sizeof(buffer), stdin);
    if (!result) return NULL;

    size_t len = strlen(buffer);
    if (len > 0 && buffer[len-1] == '\n') {
        buffer[len-1] = '\0';
    }

    char *p = buffer;
    while (*p == ' ' || *p == '\t') p++;

    if (p != buffer) {
        memmove(buffer, p, strlen(p) + 1);
    }

    return buffer;
}

static int parse_line(char *line, char ***out_args, int *out_nargs) {
    char *saveptr;
    char *tok = strtok_r(line, " \t", &saveptr);
    if (!tok) return -1;

    char **argv = malloc(MAX_ARGS * sizeof(char*));
    int i = 0;
    while (tok && i < MAX_ARGS - 1) {
        argv[i++] = tok;
        tok = strtok_r(NULL, " \t", &saveptr);
    }
    argv[i] = NULL;
    *out_args = argv;
    *out_nargs = i;
    return 0;
}

// Help
static void show_help(void) {
    fprintf(stderr,
        "\n"
        "  %s<bof.o> [args...]%s       Execute BOF (sync)\n"
        "  %s--async <bof.o> [args...]%s Run BOF in the background\n"
        "  %sjobs%s                     List BOFs in the background\n"
        "  %skill <job_id>%s            Finish BOF in the background\n"
        "  %sexit%s                     exit\n"
        "\n"
        "Args: %sstr:valor%s  %sint:valor%s  %sshort:valor%s  %swstr:valor%s\n"
        "\n"
        "Example:\n"
        "  > --async keylog_start.x64.o\n"
        "  > keylog_dump.x64.o\n"
        "  > jobs\n"
        "  > kill 0\n"
        "\n",
        g_color ? C_GRN : "", g_color ? C_RESET : "",
        g_color ? C_CYN : "", g_color ? C_RESET : "",
        g_color ? C_YEL : "", g_color ? C_RESET : "",
        g_color ? C_RED : "", g_color ? C_RESET : "",
        g_color ? C_RED : "", g_color ? C_RESET : "",
        g_color ? C_GRN : "", g_color ? C_RESET : "",
        g_color ? C_CYN : "", g_color ? C_RESET : "",
        g_color ? C_YEL : "", g_color ? C_RESET : "",
        g_color ? C_WHT : "", g_color ? C_RESET : ""
    );
    show_prompt();
}

int main(int argc, char **argv) {

    nax_bof_sdk_init();
    nax_bof_register_symbol("custom_add", custom_add);
    nax_bof_register_symbol("custom_get_info", custom_get_info);
    LOG_INFO("Custom functions registered");

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-color") == 0) {
            g_color = 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            show_help();
            return 0;
        } else {
            char **args = &argv[1];
            int nargs = argc - 1;

            int is_async = (nargs > 0 && strcmp(args[0], "--async") == 0);
            execute_bof(args, nargs);

            if (is_async) {
                update_drain_thread();
                char buf[512];
                int wait_cycles = 0;
                while (1) {
                    nax_async_list(buf, sizeof(buf));
                    if (strstr(buf, "(no active jobs)")) break;
                    struct { int flag; } ctx = {0};
                    void cb(uint32_t tid, uint8_t status, const char *out, uint32_t olen, void *ud) {
                        struct { int flag; } *c = ud;
                        async_callback(tid, status, out, olen, NULL);
                        c->flag = 1;
                    }
                    nax_async_drain(cb, &ctx);
                    struct timespec sl = {0, 100000000};
                    nanosleep(&sl, NULL);

                    wait_cycles++;
                    if (wait_cycles > 300) {
                        LOG_ERR("Timeout waiting for async job");
                        break;
                    }
                }
            }
            return 0;
        }
    }

    g_has_async_jobs = 0;

    printf("\n");
    printf("%s╔═══════════════════════════════════════════════════════╗%s\n",
           g_color ? C_BOLD : "", g_color ? C_RESET : "");
    printf("%s║              BOF Interactive Shell                  ║%s\n",
           g_color ? C_BOLD : "", g_color ? C_RESET : "");
    printf("%s║         Type 'help' for commands                   ║%s\n",
           g_color ? C_BOLD : "", g_color ? C_RESET : "");
    printf("%s╚═══════════════════════════════════════════════════════╝%s\n",
           g_color ? C_BOLD : "", g_color ? C_RESET : "");
    printf("\n");

    show_prompt();

    char *line;
    while (g_running) {
        line = read_line();
        if (!line) break;

        if (strlen(line) == 0) {
            show_prompt();
            continue;
        }

        char **args = NULL;
        int nargs = 0;
        if (parse_line(line, &args, &nargs) != 0) {
            show_prompt();
            continue;
        }

        char *cmd = args[0];

        if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
            show_help();
        } else if (strcmp(cmd, "jobs") == 0) {
            cmd_jobs();
        } else if (strcmp(cmd, "kill") == 0) {
            cmd_kill(nargs > 1 ? args[1] : NULL);
        } else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
            g_running = 0;
            char buf[512];
            nax_async_list(buf, sizeof(buf));
            if (strstr(buf, "running")) {
                LOG_INFO("Killing all running jobs...");
                for (int i = 0; i < MAX_ASYNC_JOBS; i++) {
                    nax_async_kill(i);
                }
                struct timespec sl = {0, 500000000};
                nanosleep(&sl, NULL);
            }
            free(args);
            break;
        } else if (cmd[0] == '#') {
        } else {
            execute_bof(args, nargs);
        }

        free(args);
    }

    LOG_INFO("Goodbye!");
    return 0;
}
