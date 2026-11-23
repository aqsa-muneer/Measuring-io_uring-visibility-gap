// Shared by all three eBPF monitors (syscall, LSM, io_uring/block) and by the
// userspace loaders. 
// scorer treats every monitor's CSV identically: same columns, same op codes, same meaning.
// The monitor does NOT know op_id or submission_path — those are the workload's
// ground truth. The scorer joins a monitor row to a ground-truth row by
// (path, op, tgid) inside a small time window. So a monitor only has to report:
// when, which process/thread, what kind of op, and on which path.

#ifndef IOURING_STUDY_EVENT_H
#define IOURING_STUDY_EVENT_H

#define MAX_PATH_LEN   256
#define TASK_COMM_LEN  16

/* op codes — MUST match the strings the workload writes in ground_truth.csv */
enum op_code {
    OP_READ   = 0,
    OP_WRITE  = 1,   /* overwrite (pwrite, or write to a non-append fd) */
    OP_APPEND = 2,   /* write to a fd opened O_APPEND */
};

/* One emitted detection. Fixed-size so it rides the ring buffer cleanly. */
struct event {
    unsigned long long ts_ns;            /* CLOCK_MONOTONIC ns, same clock the workload uses */
    unsigned int  tgid;                  /* process id — the attribution key */
    unsigned int  tid;                   /* thread id — may be an iou-wrk/iou-sqp worker */
    int           op;                    /* enum op_code */
    char          comm[TASK_COMM_LEN];   /* task name, e.g. "workload" or "iou-wrk-1234" */
    char          path[MAX_PATH_LEN];    /* resolved path, "" if the monitor couldn't get one */
};

#endif /* IOURING_STUDY_EVENT_H */

