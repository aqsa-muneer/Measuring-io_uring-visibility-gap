#ifndef IOURING_STUDY_MONITOR_BPF_H
#define IOURING_STUDY_MONITOR_BPF_H
#include "event.h"

#define O_APPEND 02000
#ifndef TARGET_PREFIX
#define TARGET_PREFIX "/var/tmp/iouring-study/targets/"
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} rb SEC(".maps");

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

/* stack-light prefix test (prefix stays in .rodata, not on the BPF stack) */
static __always_inline int under_target(const char *buf) {
    return bpf_strncmp(buf, sizeof(TARGET_PREFIX) - 1, TARGET_PREFIX) == 0;
}

static __always_inline void emit(int op, const char *path) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) { bump_drop(); return; }
    __u64 pt = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->tgid  = pt >> 32;
    e->tid   = (__u32)pt;
    e->op    = op;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->path, path, sizeof(e->path));
    bpf_ringbuf_submit(e, 0);
}
#endif
