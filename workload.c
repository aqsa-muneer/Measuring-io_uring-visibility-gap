//perform the SAME set of file operations against decoy targets#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <liburing.h>

/* ---- op vocabulary shared with the scorer via the ground-truth CSV ---- */
enum op_type { OP_READ, OP_WRITE, OP_APPEND };
static const char *op_name(enum op_type o) {
    switch (o) { case OP_READ: return "read";
                 case OP_WRITE: return "write";
                 default: return "append"; }
}

/* Monotonic nanosecond clock — same source the monitors should use, so
 * timestamps are comparable when the scorer matches rows by time window. */
static unsigned long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* gettid() wrapper: io_uring worker threads share our tgid (process id) but
 * have their own tid. The scorer attributes by tgid; we log both so we can
 * SHOW the tid/tgid split in the write-up rather than assume it. */
static pid_t gettid_(void) { return (pid_t)syscall(SYS_gettid); }

static FILE *gt;                 /* ground-truth log handle */
static unsigned long op_counter; /* monotonic op_id, the join key */

/* One ground-truth row. Columns match the agreed event format:
 * op_id, ts_submit_ns, mode, op, path, tgid, tid, result
 * result is filled "pending" first, then rewritten? No — simpler: we log the
 * submit row immediately, and a second status line after we know the outcome.
 * To keep the CSV one-row-per-op, we instead buffer the result and emit once.
 */
static void log_gt(unsigned long id, unsigned long long ts, const char *mode,
                   enum op_type op, const char *path, int result_errno) {
    /* result column: 0 = succeeded, else the errno of the failure.
     * The op still counts as attempted either way. */
    fprintf(gt, "%lu,%llu,%s,%s,%s,%d,%d,%d\n",
            id, ts, mode, op_name(op), path,
            (int)getpid(), (int)gettid_(), result_errno);
    fflush(gt); /* flush so a crash mid-run still leaves a usable denominator */
}


// Path 1: plain syscalls
static void do_syscall_op(const char *path, enum op_type op) {
    unsigned long id = ++op_counter;
    unsigned long long ts = now_ns();
    int result = 0;
    char buf[4096];

    if (op == OP_READ) {
        int fd = openat(AT_FDCWD, path, O_RDONLY);
        if (fd < 0) { result = errno; log_gt(id, ts, "syscall", op, path, result); return; }
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0) result = errno;
        close(fd);
    } else {
        int flags = O_WRONLY | (op == OP_APPEND ? O_APPEND : 0);
        int fd = openat(AT_FDCWD, path, flags);
        if (fd < 0) { result = errno; log_gt(id, ts, "syscall", op, path, result); return; }
        const char *line = "DECOY write via syscall path\n";
        /* append uses write (respects O_APPEND); overwrite uses pwrite at 0 */
        ssize_t n = (op == OP_APPEND)
                      ? write(fd, line, strlen(line))
                      : pwrite(fd, line, strlen(line), 0);
        if (n < 0) result = errno;
        close(fd);
    }
    log_gt(id, ts, "syscall", op, path, result);
}

// Path 2 & 3: io_uring (sqpoll adds the SQPOLL flag at setup)
static void do_uring_op(struct io_uring *ring, const char *mode,
                        const char *path, enum op_type op) {
    unsigned long id = ++op_counter;
    unsigned long long ts = now_ns(); /* submission time, logged below */
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    static char buf[4096];
    int result = 0, fd = -1;

    /* --- SQE 1: open via the ring --- */
    sqe = io_uring_get_sqe(ring);
    int oflags = (op == OP_READ) ? O_RDONLY
               : O_WRONLY | (op == OP_APPEND ? O_APPEND : 0);
    io_uring_prep_openat(sqe, AT_FDCWD, path, oflags, 0);
    io_uring_submit(ring);                 /* on sqpoll this may not even enter */
    io_uring_wait_cqe(ring, &cqe);
    fd = cqe->res;                          /* negative = -errno */
    io_uring_cqe_seen(ring, cqe);
    if (fd < 0) { result = -fd; log_gt(id, ts, mode, op, path, result); return; }

    /* --- SQE 2: the read or write, also via the ring --- */
    sqe = io_uring_get_sqe(ring);
    if (op == OP_READ) {
        io_uring_prep_read(sqe, fd, buf, sizeof buf, 0);
    } else {
        const char *line = "DECOY write via io_uring path\n";
        /* offset -1 with O_APPEND appends; offset 0 overwrites the head */
        off_t off = (op == OP_APPEND) ? (off_t)-1 : 0;
        io_uring_prep_write(sqe, fd, line, strlen(line), off);
    }
    io_uring_submit(ring);
    io_uring_wait_cqe(ring, &cqe);
    if (cqe->res < 0) result = -cqe->res;
    io_uring_cqe_seen(ring, cqe);

    /* --- SQE 3: close via the ring (keeps even the close off the syscall path) --- */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_close(sqe, fd);
    io_uring_submit(ring);
    io_uring_wait_cqe(ring, &cqe);
    io_uring_cqe_seen(ring, cqe);

    log_gt(id, ts, mode, op, path, result);
}

int main(int argc, char **argv) {
    const char *mode = "syscall";
    const char *targetdir = "/tmp/iouring-study/targets";
    const char *gtpath = "/tmp/iouring-study/ground_truth.csv";
    int reps = 1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--mode") && i + 1 < argc)      mode = argv[++i];
        else if (!strcmp(argv[i], "--targets") && i + 1 < argc) targetdir = argv[++i];
        else if (!strcmp(argv[i], "--gt") && i + 1 < argc)   gtpath = argv[++i];
        else if (!strcmp(argv[i], "--reps") && i + 1 < argc) reps = atoi(argv[++i]);
        else { fprintf(stderr,
            "usage: %s --mode syscall|uring|sqpoll [--targets DIR] [--gt FILE] [--reps N]\n",
            argv[0]); return 2; }
    }

    gt = fopen(gtpath, "a");
    if (!gt) { perror("open ground truth"); return 1; }
    /* header once, if file is empty */
    fseek(gt, 0, SEEK_END);
    if (ftell(gt) == 0)
        fprintf(gt, "op_id,ts_submit_ns,mode,op,path,tgid,tid,result_errno\n");

    /* Build the three target paths. */
    char shadow[512], key[512], audit[512];
    snprintf(shadow, sizeof shadow, "%s/shadow.decoy", targetdir);
    snprintf(key,    sizeof key,    "%s/id_rsa.decoy", targetdir);
    snprintf(audit,  sizeof audit,  "%s/audit.decoy.log", targetdir);

    const char *targets[] = { shadow, key, audit };
    enum op_type ops[] = { OP_READ, OP_WRITE, OP_APPEND };

    if (!strcmp(mode, "syscall")) {
        for (int r = 0; r < reps; r++)
            for (int t = 0; t < 3; t++)
                for (int o = 0; o < 3; o++)
                    do_syscall_op(targets[t], ops[o]);
    } else {
        /* uring and sqpoll share a ring; sqpoll just sets the poll flag. */
        struct io_uring ring;
        struct io_uring_params p;
        memset(&p, 0, sizeof p);
        if (!strcmp(mode, "sqpoll")) {
            p.flags |= IORING_SETUP_SQPOLL;
            p.sq_thread_idle = 2000; /* ms the kernel poll thread idles before sleeping */
        } else if (strcmp(mode, "uring")) {
            fprintf(stderr, "unknown mode: %s\n", mode); return 2;
        }
        if (io_uring_queue_init_params(256, &ring, &p) < 0) {
            perror("io_uring_queue_init_params");
            fprintf(stderr, "SQPOLL often needs root or CAP_SYS_NICE on older kernels.\n");
            return 1;
        }
        for (int r = 0; r < reps; r++)
            for (int t = 0; t < 3; t++)
                for (int o = 0; o < 3; o++)
                    do_uring_op(&ring, mode, targets[t], ops[o]);
        io_uring_queue_exit(&ring);
    }

    fclose(gt);
    fprintf(stderr, "done: mode=%s reps=%d ops=%lu\n", mode, reps, op_counter);
    return 0;
}