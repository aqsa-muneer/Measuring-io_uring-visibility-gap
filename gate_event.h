//reports *decisions* about io_uring_setup() calls

#ifndef GATE_EVENT_H
#define GATE_EVENT_H

#define GATE_COMM_LEN 16

/* Identity of an executable: the (device, inode) of the process's binary.
 * dev uses the KERNEL encoding of dev_t: (major << 20) | minor. The loader
 * converts userspace st_dev into this form before inserting allowlist keys. */
struct exe_key {
    __u32 dev;
    __u32 _pad;      /* explicit padding so BPF and userspace agree on layout */
    __u64 ino;
};

/* config map slot indices */
#define CFG_ENFORCE 0   /* 1 = return -EPERM, 0 = audit only (log, allow) */
#define CFG_NSLOTS  1

/* verdicts written to the ring buffer */
#define VERDICT_DENIED     1   /* enforce mode: setup refused with -EPERM   */
#define VERDICT_WOULD_DENY 2   /* audit mode: not allowlisted, but let through */

struct gate_event {
    __u64 ts_ns;            /* bpf_ktime_get_ns() == CLOCK_MONOTONIC */
    __u32 tgid;
    __u32 tid;
    __u32 verdict;
    __u32 _pad;
    struct exe_key exe;
    char  comm[GATE_COMM_LEN];
};

#endif