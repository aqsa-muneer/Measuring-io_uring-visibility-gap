// cost of the gate on the thing it gates: io_uring_setup().
// ./setup_bench [N]      (default N = 100000)
// Times N x (io_uring_setup + close) using the raw syscall, so we measure
// the syscall itself and not liburing's mmap work. 
// Run three ways:
// 1. no gate loaded                       -> baseline
// 2. gate loaded, setup_bench allowlisted -> cost of the allowed fast path
// 3. gate --enforce, NOT allowlisted      -> cost of the deny path
// The gate runs once per ring, not once per I/O, so per-I/O throughput
// should be unchanged; this shows how small the per-ring cost is.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>

static unsigned long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 100000;
    long ok = 0, failed = 0;
    int first_errno = 0;

    /* warm-up so the first-call costs (page faults, caches) don't skew it */
    for (int i = 0; i < 100; i++) {
        struct io_uring_params p; memset(&p, 0, sizeof p);
        int fd = syscall(__NR_io_uring_setup, 8, &p);
        if (fd >= 0) close(fd);
    }

    unsigned long long t0 = now_ns();
    for (long i = 0; i < n; i++) {
        struct io_uring_params p; memset(&p, 0, sizeof p);
        int fd = syscall(__NR_io_uring_setup, 8, &p);
        if (fd >= 0) { close(fd); ok++; }
        else { failed++; if (!first_errno) first_errno = errno; }
    }
    unsigned long long dt = now_ns() - t0;

    printf("n,ok,failed,first_errno,total_ns,ns_per_call\n");
    printf("%ld,%ld,%ld,%d,%llu,%.1f\n", n, ok, failed, first_errno, dt, (double)dt / n);
    return 0;
}