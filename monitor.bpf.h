// monitor.bpf.h — BPF-side bits every monitor shares.
// The syscall monitor (written first) has its own inline copies of these; from
// the LSM monitor onward we factor them here so all monitors use the SAME ring
// buffer, the SAME drop counter, the SAME target-path filter, and emit the SAME
// event. Map names (rb, drops) are part of the contract: the generic loader
// finds them by name, so every monitor must keep these names.
 
#ifndef IOURING_STUDY_MONITOR_BPF_H
#define IOURING_STUDY_MONITOR_BPF_H

#include "event.h"

/* O_APPEND isn't in vmlinux.h; same value on x86 and arm64 */
#define O_APPEND 02000

/* must match the workload's --targets dir; end with a slash */
#ifndef TARGET_PREFIX
#define TARGET_PREFIX "/tmp/iouring-study/targets/"
#endif

/* the ring buffer the loader drains */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);        /* 1 MiB */
} rb SEC(".maps");

/* reserve failures = events we had to drop (the "dropped events" metric) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

static __always_inline void bump_drop(void) {
    __u32 z = 0;
    __u64 *d = bpf_map_lookup_elem(&drops, &z);
    if (d) __sync_fetch_and_add(d, 1);
}

/* fixed-length prefix test against TARGET_PREFIX (buf already copied in) */
static __always_inline int under_target(const char *buf) {
    const char pref[] = TARGET_PREFIX;
#pragma unroll
    for (int i = 0; i < (int)sizeof(pref) - 1; i++)
        if (buf[i] != pref[i]) return 0;
    return 1;
}

/* emit one detection: current task + op + an already-resolved path string */
static __always_inline void emit(int op, const char *path) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) { bump_drop(); return; }
    __u64 pt = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->tgid  = pt >> 32;                  /* process id — the attribution key */
    e->tid   = (__u32)pt;                 /* thread id — may be an iou-wrk/iou-sqp worker */
    e->op    = op;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->path, path, sizeof(e->path));
    bpf_ringbuf_submit(e, 0);
}

#endif /* IOURING_STUDY_MONITOR_BPF_H */