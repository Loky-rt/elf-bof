/* bof_async.c — Async BOF job system
 * Manages background BOF execution threads with result queuing.
 */

#include "bof_async.h"
#include "elf_bof.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <poll.h>

static async_job_t g_jobs[MAX_ASYNC_JOBS];
static pthread_mutex_t g_jobs_lock = PTHREAD_MUTEX_INITIALIZER;

/* Thread-local stop fd — set by async thread, read by BeaconGetStopJobEvent */
static __thread int tls_stop_fd = -1;

void nax_async_init(void) {
    memset(g_jobs, 0, sizeof(g_jobs));
    for (int i = 0; i < MAX_ASYNC_JOBS; i++) {
        g_jobs[i].state       = NAX_JOB_FREE;
        g_jobs[i].stop_pipe[0] = -1;
        g_jobs[i].stop_pipe[1] = -1;
    }
}

int nax_async_get_stop_fd(void) {
    return tls_stop_fd;
}

/* ── Worker thread ── */

static void *bof_worker(void *param) {
    async_job_t *job = (async_job_t *)param;

    /* Set TLS stop fd so BeaconGetStopJobEvent can return it */
    tls_stop_fd = job->stop_pipe[0];

    /* Execute BOF synchronously in this thread.
     * bof_api.c output globals are __thread, so each thread has its own buffer. */
    char    *output     = NULL;
    uint32_t output_len = 0;
    int rc = nax_bof_execute(job->bof_data, job->bof_size,
                             job->args_data, job->args_size,
                             "go", &output, &output_len);

    /* Save local copies of data pointers before taking the lock.
     * After setting state=COMPLETED, drain() may reset the slot at any time. */
    uint8_t *bof_copy  = job->bof_data;
    uint32_t bof_sz    = job->bof_size;
    uint8_t *args_copy = job->args_data;
    uint32_t args_sz   = job->args_size;

    pthread_mutex_lock(&g_jobs_lock);
    job->bof_data  = NULL;  /* nulled before COMPLETED so drain's memset is safe */
    job->args_data = NULL;
    if (job->killed) {
        /* Job was killed — discard output and mark FREE so the slot is reused.
         * Do NOT set COMPLETED: drain() must not deliver a result for a killed job,
         * and the slot must not remain occupied blocking future async BOFs. */
        if (output) { free(output); output = NULL; }
        if (job->stop_pipe[0] >= 0) close(job->stop_pipe[0]);
        if (job->stop_pipe[1] >= 0) close(job->stop_pipe[1]);
        memset(job, 0, sizeof(*job));
        job->state        = NAX_JOB_FREE;
        job->stop_pipe[0] = -1;
        job->stop_pipe[1] = -1;
    } else {
        job->output     = output;
        job->output_len = output_len;
        job->status     = (rc == 0) ? NAX_STATUS_OK : NAX_STATUS_ERR;
        job->state      = NAX_JOB_COMPLETED; /* drain() may reset slot after this */
    }
    pthread_mutex_unlock(&g_jobs_lock);

    /* Zero and free using local copies — job pointer is no longer safe to use */
    if (bof_copy) {
        volatile uint8_t *p = (volatile uint8_t *)bof_copy;
        for (uint32_t i = 0; i < bof_sz; i++) p[i] = 0;
        free(bof_copy);
    }
    if (args_copy) {
        volatile uint8_t *p = (volatile uint8_t *)args_copy;
        for (uint32_t i = 0; i < args_sz; i++) p[i] = 0;
        free(args_copy);
    }

    tls_stop_fd = -1;
    return NULL;
}

/* ────────────────────────── Public API ────────────────────────── */

int nax_async_start(uint32_t task_id,
                    const uint8_t *bof_data, uint32_t bof_size,
                    const uint8_t *args_data, uint32_t args_size) {
    /* Validate inputs — if we return a valid job ID, the job owns all its data */
    if (!bof_data || bof_size == 0) return -1;

    pthread_mutex_lock(&g_jobs_lock);

    /* Find free slot */
    int idx = -1;
    for (int i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_jobs[i].state == NAX_JOB_FREE) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        pthread_mutex_unlock(&g_jobs_lock);
        return -1; /* all slots busy */
    }

    async_job_t *job = &g_jobs[idx];
    memset(job, 0, sizeof(*job));
    job->state        = NAX_JOB_FREE; /* will be set to RUNNING after setup */
    job->stop_pipe[0] = -1;
    job->stop_pipe[1] = -1;

    /* Deep copy BOF data */
    job->bof_data = (uint8_t *)malloc(bof_size);
    if (!job->bof_data) {
        pthread_mutex_unlock(&g_jobs_lock);
        return -1;
    }
    memcpy(job->bof_data, bof_data, bof_size);
    job->bof_size = bof_size;

    /* Deep copy args — explicit failure if malloc fails */
    if (args_data && args_size > 0) {
        job->args_data = (uint8_t *)malloc(args_size);
        if (!job->args_data) {
            free(job->bof_data);
            job->bof_data = NULL;
            pthread_mutex_unlock(&g_jobs_lock);
            return -1;
        }
        memcpy(job->args_data, args_data, args_size);
        job->args_size = args_size;
    }

    job->task_id = task_id;

    /* Create stop pipe */
    if (pipe(job->stop_pipe) != 0) {
        job->stop_pipe[0] = job->stop_pipe[1] = -1;
    }

    /* Set RUNNING before pthread_create so the worker never sees FREE state.
     * The mutex is still held here, so drain()/kill()/list() are blocked until
     * we release it — the worker can start immediately but it only reads
     * bof_data/args_data which are fully initialized before this point. */
    job->state = NAX_JOB_RUNNING;

    if (pthread_create(&job->thread, NULL, bof_worker, job) != 0) {
        /* Rollback — slot must be fully clean before releasing lock */
        job->state = NAX_JOB_FREE;
        free(job->bof_data);
        job->bof_data = NULL;
        if (job->args_data) {
            free(job->args_data);
            job->args_data = NULL;
        }
        if (job->stop_pipe[0] >= 0) close(job->stop_pipe[0]);
        if (job->stop_pipe[1] >= 0) close(job->stop_pipe[1]);
        job->stop_pipe[0] = -1;
        job->stop_pipe[1] = -1;
        pthread_mutex_unlock(&g_jobs_lock);
        return -1;
    }

    pthread_detach(job->thread);
    pthread_mutex_unlock(&g_jobs_lock);
    return idx;
}

void nax_async_drain(async_result_cb cb, void *user_data) {
    for (int i = 0; i < MAX_ASYNC_JOBS; i++) {
        pthread_mutex_lock(&g_jobs_lock);
        if (g_jobs[i].state != NAX_JOB_COMPLETED) {
            pthread_mutex_unlock(&g_jobs_lock);
            continue;
        }

        /* Copy result out of the slot before releasing the lock.
         * This avoids holding g_jobs_lock during network I/O in the callback,
         * which would block nax_async_kill() from writing to stop_pipe. */
        uint32_t task_id    = g_jobs[i].task_id;
        uint8_t  status     = g_jobs[i].status;
        char    *output     = g_jobs[i].output;
        uint32_t output_len = g_jobs[i].output_len;

        /* Close stop pipe and reset slot while we still hold the lock */
        if (g_jobs[i].stop_pipe[0] >= 0) close(g_jobs[i].stop_pipe[0]);
        if (g_jobs[i].stop_pipe[1] >= 0) close(g_jobs[i].stop_pipe[1]);
        memset(&g_jobs[i], 0, sizeof(g_jobs[i]));
        g_jobs[i].state        = NAX_JOB_FREE;
        g_jobs[i].stop_pipe[0] = -1;
        g_jobs[i].stop_pipe[1] = -1;

        pthread_mutex_unlock(&g_jobs_lock);

        /* Deliver result outside the lock — network I/O happens here */
        if (cb) cb(task_id, status, output, output_len, user_data);
        if (output) free(output);
    }
}

int nax_async_kill(int job_idx) {
    if (job_idx < 0 || job_idx >= MAX_ASYNC_JOBS) return -1;
    pthread_mutex_lock(&g_jobs_lock);
    async_job_t *job = &g_jobs[job_idx];
    if (job->state != NAX_JOB_RUNNING) {
        pthread_mutex_unlock(&g_jobs_lock);
        return -1;
    }
    /* Mark as killed so the worker thread skips result delivery.
     * This prevents the thread from writing output into a slot that
     * may be reset by drain() before the thread finishes executing. */
    job->killed = 1;
    /* Signal the BOF to stop via the pipe */
    if (job->stop_pipe[1] >= 0) {
        char c = 1;
        (void)write(job->stop_pipe[1], &c, 1);
    }
    pthread_mutex_unlock(&g_jobs_lock);
    return 0;
}

int nax_async_list(char *buf, int cap) {
    int n = 0;
    pthread_mutex_lock(&g_jobs_lock);
    for (int i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_jobs[i].state != NAX_JOB_FREE) {
            const char *state_str = (g_jobs[i].state == NAX_JOB_RUNNING)
                                    ? "running" : "completed";
            int w = snprintf(buf + n, cap - n, "  Job #%d  task=%u  %s\n",
                             i, g_jobs[i].task_id, state_str);
            if (w > 0) n += w;
        }
    }
    pthread_mutex_unlock(&g_jobs_lock);
    if (n == 0) n = snprintf(buf, cap, "  (no active jobs)\n");
    return n;
}
