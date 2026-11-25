#define _GNU_SOURCE
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

/* Monotonic nanosecond clock — same source the monitors use (bpf_ktime_get_ns),
 * so the scorer can match rows by time window. */
static unsigned long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* io_uring worker threads share our tgid but have their own tid; log both. */
static pid_t gettid_(void) { return (pid_t)syscall(SYS_gettid); }

static FILE *gt;                 /* ground-truth log handle */
static unsigned long op_counter; /* monotonic op_id */
static int setup_errno_g;        /* errno from io_uring setup for this run (0 = ok / n/a) */

#define GT_HEADER "op_id,ts_submit_ns,mode,op,path,tgid,tid,result_errno,path_used,setup_errno\n"

static void log_gt(unsigned long id, unsigned long long ts, const char *mode,
                   enum op_type op, const char *path, int result_errno,
                   const char *path_used) {
    fprintf(gt, "%lu,%llu,%s,%s,%s,%d,%d,%d,%s,%d\n",
            id, ts, mode, op_name(op), path,
            (int)getpid(), (int)gettid_(), result_errno,
            path_used, setup_errno_g);
    fflush(gt); /* a crash mid-run still leaves a usable denominator */
}

/* =====================================================================
 * PATH 1: plain syscalls. `mode` is the label for the CSV: "syscall" for a
 * normal run, or "uring"/"sqpoll" when this is a fallback after the gate
 * refused io_uring setup.
 * ===================================================================== */
static void do_syscall_op(const char *mode, const char *path, enum op_type op) {
    unsigned long id = ++op_counter;
    unsigned long long ts = now_ns();
    int result = 0;
    char buf[4096];

    if (op == OP_READ) {
        int fd = openat(AT_FDCWD, path, O_RDONLY);
        if (fd < 0) { result = errno; log_gt(id, ts, mode, op, path, result, "syscall"); return; }
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0) result = errno;
        close(fd);
    } else {
        int flags = O_WRONLY | (op == OP_APPEND ? O_APPEND : 0);
        int fd = openat(AT_FDCWD, path, flags);
        if (fd < 0) { result = errno; log_gt(id, ts, mode, op, path, result, "syscall"); return; }
        const char *line = "DECOY write via syscall path\n";
        /* append uses write (respects O_APPEND); overwrite uses pwrite at 0 */
        ssize_t n = (op == OP_APPEND)
                      ? write(fd, line, strlen(line))
                      : pwrite(fd, line, strlen(line), 0);
        if (n < 0) result = errno;
        close(fd);
    }
    log_gt(id, ts, mode, op, path, result, "syscall");
}

/* =====================================================================
 * PATH 2 & 3: io_uring (sqpoll adds the SQPOLL flag at setup)
 * The open is ALSO an SQE (IORING_OP_OPENAT), so the whole op — open,
 * read/write, close — stays off the syscall path.
 * ===================================================================== */
static void do_uring_op(struct io_uring *ring, const char *mode,
                        const char *path, enum op_type op) {
    unsigned long id = ++op_counter;
    unsigned long long ts = now_ns();
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    static char buf[4096];
    int result = 0, fd = -1;

    /* --- SQE 1: open via the ring --- */
    sqe = io_uring_get_sqe(ring);
    int oflags = (op == OP_READ) ? O_RDONLY
               : O_WRONLY | (op == OP_APPEND ? O_APPEND : 0);
    io_uring_prep_openat(sqe, AT_FDCWD, path, oflags, 0);
    io_uring_submit(ring);
    io_uring_wait_cqe(ring, &cqe);
    fd = cqe->res;                          /* negative = -errno */
    io_uring_cqe_seen(ring, cqe);
    if (fd < 0) { result = -fd; log_gt(id, ts, mode, op, path, result, mode); return; }

    /* --- SQE 2: the read or write --- */
    sqe = io_uring_get_sqe(ring);
    if (op == OP_READ) {
        io_uring_prep_read(sqe, fd, buf, sizeof buf, 0);
    } else {
        const char *line = "DECOY write via io_uring path\n";
        off_t off = (op == OP_APPEND) ? (off_t)-1 : 0;   /* -1 + O_APPEND = append */
        io_uring_prep_write(sqe, fd, line, strlen(line), off);
    }
    io_uring_submit(ring);
    io_uring_wait_cqe(ring, &cqe);
    if (cqe->res < 0) result = -cqe->res;
    io_uring_cqe_seen(ring, cqe);

    /* --- SQE 3: close via the ring --- */
    sqe = io_uring_get_sqe(ring);
    io_uring_prep_close(sqe, fd);
    io_uring_submit(ring);
    io_uring_wait_cqe(ring, &cqe);
    io_uring_cqe_seen(ring, cqe);

    log_gt(id, ts, mode, op, path, result, mode);
}

/* Blocked op: setup was refused and --fallback is off. Nothing touches the
 * file, but it was attempted, so it still gets a row (result = setup errno). */
static void log_blocked(const char *mode, const char *path, enum op_type op) {
    unsigned long id = ++op_counter;
    log_gt(id, now_ns(), mode, op, path, setup_errno_g, "none");
}

/* Refuse to append new-format rows under an old-format header: pandas would
 * mis-parse the file. Use a fresh --gt file for gate runs. */
static int header_ok(FILE *f) {
    char first[256] = "";
    rewind(f);
    if (!fgets(first, sizeof first, f)) return 1;      /* empty file: fine */
    return strstr(first, "path_used") != NULL;
}

int main(int argc, char **argv) {
    const char *mode = "syscall";
    const char *targetdir = "/tmp/iouring-study/targets";
    const char *gtpath = "/tmp/iouring-study/ground_truth.csv";
    int reps = 1, fallback = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--mode") && i + 1 < argc)         mode = argv[++i];
        else if (!strcmp(argv[i], "--targets") && i + 1 < argc) targetdir = argv[++i];
        else if (!strcmp(argv[i], "--gt") && i + 1 < argc)      gtpath = argv[++i];
        else if (!strcmp(argv[i], "--reps") && i + 1 < argc)    reps = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--fallback"))                fallback = 1;
        else { fprintf(stderr,
            "usage: %s --mode syscall|uring|sqpoll [--fallback] [--targets DIR] [--gt FILE] [--reps N]\n",
            argv[0]); return 2; }
    }
    if (strcmp(mode, "syscall") && strcmp(mode, "uring") && strcmp(mode, "sqpoll")) {
        fprintf(stderr, "unknown mode: %s\n", mode); return 2;
    }

    gt = fopen(gtpath, "a+");
    if (!gt) { perror("open ground truth"); return 1; }
    if (!header_ok(gt)) {
        fprintf(stderr, "%s has the old 8-column header. Use a fresh --gt file "
                        "(or delete it) so old and new rows don't mix.\n", gtpath);
        return 1;
    }
    fseek(gt, 0, SEEK_END);
    if (ftell(gt) == 0) fputs(GT_HEADER, gt);

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
                    do_syscall_op("syscall", targets[t], ops[o]);
    } else {
        struct io_uring ring;
        struct io_uring_params p;
        memset(&p, 0, sizeof p);
        if (!strcmp(mode, "sqpoll")) {
            p.flags |= IORING_SETUP_SQPOLL;
            p.sq_thread_idle = 2000;   /* ms before the poll thread sleeps */
        }
        /* liburing returns -errno directly; it does NOT set errno. */
        int ret = io_uring_queue_init_params(256, &ring, &p);
        if (ret < 0) {
            setup_errno_g = -ret;
            fprintf(stderr, "io_uring setup refused: %s%s\n", strerror(-ret),
                    fallback ? " -> falling back to plain syscalls" : " -> ops blocked");
            for (int r = 0; r < reps; r++)
                for (int t = 0; t < 3; t++)
                    for (int o = 0; o < 3; o++) {
                        if (fallback) do_syscall_op(mode, targets[t], ops[o]);
                        else          log_blocked(mode, targets[t], ops[o]);
                    }
        } else {
            for (int r = 0; r < reps; r++)
                for (int t = 0; t < 3; t++)
                    for (int o = 0; o < 3; o++)
                        do_uring_op(&ring, mode, targets[t], ops[o]);
            io_uring_queue_exit(&ring);
        }
    }

    fclose(gt);
    fprintf(stderr, "done: mode=%s reps=%d ops=%lu%s\n", mode, reps, op_counter,
            setup_errno_g ? (fallback ? " (via fallback)" : " (blocked)") : "");
    return 0;
}