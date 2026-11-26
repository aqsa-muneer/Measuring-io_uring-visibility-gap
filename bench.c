// bench.c — overhead benchmark for the io_uring visibility study.
//
// This is the COST half of the project. Where workload.c issues a tiny,
// deterministic set of ops to measure DETECTION, bench.c hammers one decoy file
// with a high volume of open+op+close iterations to measure what each monitor
// COSTS: throughput, per-op latency, and the workload's own CPU. It drives the
// exact same code paths the monitors hook (openat for syscall/LSM/uring_tp,
// direct block I/O for block), so the slowdown it records is the real cost of
// having that monitor attached.
//
// It deliberately targets a decoy path (matches the monitor's filter), so every
// iteration makes the monitor emit an event — this is also what stresses the
// ring buffer and lets the harness measure DROPPED events under load.
//
// Output: one machine-readable CSV line on stdout, a human summary on stderr.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <liburing.h>

#define BLK 4096

enum op_type { OP_READ, OP_WRITE, OP_APPEND };

static unsigned long long now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
static int cmp_u64(const void *a, const void *b) {
    unsigned long long x = *(const unsigned long long *)a, y = *(const unsigned long long *)b;
    return (x > y) - (x < y);
}

static int   g_direct;
static void *g_abuf;          /* page-aligned bounce buffer for O_DIRECT */

/* one syscall-mode iteration: open + one op + close. returns latency in ns. */
static unsigned long long iter_syscall(const char *path, enum op_type op) {
    char buf[BLK];
    unsigned long long t0 = now_ns();
    int flags = g_direct ? ((op == OP_READ) ? (O_RDONLY | O_DIRECT) : (O_WRONLY | O_DIRECT))
                         : ((op == OP_READ) ? O_RDONLY : (O_WRONLY | (op == OP_APPEND ? O_APPEND : 0)));
    int fd = openat(AT_FDCWD, path, flags);
    if (fd >= 0) {
        ssize_t r;
        if (op == OP_READ) {
            r = g_direct ? pread(fd, g_abuf, BLK, 0) : read(fd, buf, sizeof buf);
        } else if (g_direct) {
            r = pwrite(fd, g_abuf, BLK, (op == OP_APPEND) ? BLK : 0);
        } else {
            r = pwrite(fd, "x\n", 2, 0);                   /* offset 0: no unbounded growth */
        }
        (void)r;
        close(fd);
    }
    return now_ns() - t0;
}

/* one io_uring-mode iteration: open + one op + close, all via the ring. */
static unsigned long long iter_uring(struct io_uring *ring, const char *path, enum op_type op) {
    struct io_uring_sqe *sqe; struct io_uring_cqe *cqe; static char buf[BLK];
    unsigned long long t0 = now_ns();
    int flags = g_direct ? ((op == OP_READ) ? (O_RDONLY | O_DIRECT) : (O_WRONLY | O_DIRECT))
                         : ((op == OP_READ) ? O_RDONLY : (O_WRONLY | (op == OP_APPEND ? O_APPEND : 0)));
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_openat(sqe, AT_FDCWD, path, flags, 0);
    io_uring_submit(ring); io_uring_wait_cqe(ring, &cqe);
    int fd = cqe->res; io_uring_cqe_seen(ring, cqe);
    if (fd >= 0) {
        sqe = io_uring_get_sqe(ring);
        if (op == OP_READ) {
            io_uring_prep_read(sqe, fd, g_direct ? g_abuf : (void *)buf, BLK, 0);
        } else {
            void *src = g_direct ? g_abuf : (void *)"x\n";
            unsigned len = g_direct ? BLK : 2;
            off_t off = (op == OP_APPEND) ? (g_direct ? BLK : (off_t)-1) : 0;
            io_uring_prep_write(sqe, fd, src, len, off);
        }
        io_uring_submit(ring); io_uring_wait_cqe(ring, &cqe); io_uring_cqe_seen(ring, cqe);
        sqe = io_uring_get_sqe(ring); io_uring_prep_close(sqe, fd);
        io_uring_submit(ring); io_uring_wait_cqe(ring, &cqe); io_uring_cqe_seen(ring, cqe);
    }
    return now_ns() - t0;
}

int main(int argc, char **argv) {
    const char *mode = "syscall";
    const char *path = "/var/tmp/iouring-study/targets/shadow.decoy";
    enum op_type op = OP_READ;
    long iters = 100000;
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--mode")   && i + 1 < argc) mode = argv[++i];
        else if (!strcmp(argv[i], "--target") && i + 1 < argc) path = argv[++i];
        else if (!strcmp(argv[i], "--iters")  && i + 1 < argc) iters = atol(argv[++i]);
        else if (!strcmp(argv[i], "--direct")) g_direct = 1;
        else if (!strcmp(argv[i], "--op")     && i + 1 < argc) {
            const char *o = argv[++i];
            op = !strcmp(o, "write") ? OP_WRITE : !strcmp(o, "append") ? OP_APPEND : OP_READ;
        } else {
            fprintf(stderr, "usage: %s --mode syscall|uring|sqpoll [--op read|write|append] "
                            "[--direct] [--iters N] [--target FILE]\n", argv[0]);
            return 2;
        }
    }
    if (iters < 1) iters = 1;
    if (g_direct) {
        if (posix_memalign(&g_abuf, BLK, BLK) != 0) { perror("posix_memalign"); return 1; }
        memset(g_abuf, 0xAB, BLK);
    }
    unsigned long long *lat = malloc(sizeof(*lat) * (size_t)iters);
    if (!lat) { perror("malloc"); return 1; }

    struct io_uring ring; int use_ring = 0;
    if (strcmp(mode, "syscall") != 0) {
        struct io_uring_params p; memset(&p, 0, sizeof p);
        if      (!strcmp(mode, "sqpoll")) { p.flags |= IORING_SETUP_SQPOLL; p.sq_thread_idle = 2000; }
        else if (strcmp(mode, "uring") != 0) { fprintf(stderr, "bad mode %s\n", mode); return 2; }
        if (io_uring_queue_init_params(256, &ring, &p) < 0) {
            perror("io_uring_queue_init_params");
            fprintf(stderr, "SQPOLL often needs root or CAP_SYS_NICE.\n");
            return 1;
        }
        use_ring = 1;
    }

    struct rusage ru0, ru1; getrusage(RUSAGE_SELF, &ru0);
    unsigned long long wall0 = now_ns();
    for (long i = 0; i < iters; i++)
        lat[i] = use_ring ? iter_uring(&ring, path, op) : iter_syscall(path, op);
    unsigned long long wall = now_ns() - wall0;
    getrusage(RUSAGE_SELF, &ru1);
    if (use_ring) io_uring_queue_exit(&ring);

    qsort(lat, iters, sizeof(*lat), cmp_u64);
    double wall_s = wall / 1e9;
    double tput   = iters / wall_s;
    unsigned long long sum = 0; for (long i = 0; i < iters; i++) sum += lat[i];
    double mean_us = (sum / (double)iters) / 1000.0;
    double p50  = lat[iters / 2] / 1000.0;
    double p99  = lat[(long)(iters * 0.99)] / 1000.0;
    double p999 = lat[(long)(iters * 0.999)] / 1000.0;
    double cpu_s = ((ru1.ru_utime.tv_sec - ru0.ru_utime.tv_sec)
                    + (ru1.ru_stime.tv_sec - ru0.ru_stime.tv_sec))
                 + ((ru1.ru_utime.tv_usec - ru0.ru_utime.tv_usec)
                    + (ru1.ru_stime.tv_usec - ru0.ru_stime.tv_usec)) / 1e6;

    const char *opn = op == OP_READ ? "read" : op == OP_WRITE ? "write" : "append";
    /* CSV: mode,op,direct,iters,wall_s,throughput,lat_mean_us,p50_us,p99_us,p999_us,workload_cpu_s */
    printf("%s,%s,%d,%ld,%.4f,%.1f,%.3f,%.3f,%.3f,%.3f,%.4f\n",
           mode, opn, g_direct, iters, wall_s, tput, mean_us, p50, p99, p999, cpu_s);
    fprintf(stderr, "bench %s/%s direct=%d iters=%ld: %.0f ops/s  p50=%.1fus p99=%.1fus  cpu=%.2fs\n",
            mode, opn, g_direct, iters, tput, p50, p99, cpu_s);
    free(lat); if (g_abuf) free(g_abuf);
    return 0;
}
