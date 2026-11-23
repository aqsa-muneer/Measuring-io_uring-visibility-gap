// hooks the syscall entry/exit tracepoints and nothing deeper. this monitor is near-perfect on the plain-syscall path and
// goes blind on the io_uring paths — because io_uring reads/writes never pass through these syscall tracepoints at all.

#include "vmlinux.h"            /* generated on the VM: bpftool btf dump ... */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "event.h"

char LICENSE[] SEC("license") = "GPL";

/* O_APPEND isn't in vmlinux.h; define it (same on x86 and arm64). */
#define O_APPEND 02000

/* Change this if you pass a different --targets dir to the workload.
 * It must end with a slash and match the absolute path the workload opens. */
#define TARGET_PREFIX "/tmp/iouring-study/targets/"

/* ---- maps -------------------------------------------------------------- */

/* open() in progress, keyed by tid (enter and exit run on the same thread) */
struct openscratch { __u64 fname_ptr; int flags; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);                 /* tid */
    __type(value, struct openscratch);
} open_scratch SEC(".maps");

/* fd -> path mapping we care about, keyed by (tgid<<32 | fd) */
struct fdinfo { char path[MAX_PATH_LEN]; __u8 is_append; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct fdinfo);
} fd_paths SEC(".maps");

/* the ring buffer the loader drains */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);       /* 1 MiB */
} rb SEC(".maps");

/* single-counter drop tally: reserve failures = events we had to drop */
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

/* fixed-length prefix test against TARGET_PREFIX (buf is already copied in) */
static __always_inline int under_target(const char *buf) {
    const char pref[] = TARGET_PREFIX;
#pragma unroll
    for (int i = 0; i < (int)sizeof(pref) - 1; i++)
        if (buf[i] != pref[i]) return 0;
    return 1;
}

/* emit one detection for the current task on the given fd */
static __always_inline void emit(int op, struct fdinfo *fi) {
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) { bump_drop(); return; }
    __u64 pt = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->tgid  = pt >> 32;
    e->tid   = (__u32)pt;
    e->op    = op;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->path, fi->path, sizeof(e->path));
    bpf_ringbuf_submit(e, 0);
}

/* ---- openat: learn fd -> path ----------------------------------------- */

SEC("tp/syscalls/sys_enter_openat")
int on_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct openscratch s = {};
    s.fname_ptr = (__u64)ctx->args[1];     /* const char *filename */
    s.flags     = (int)ctx->args[2];       /* flags */
    bpf_map_update_elem(&open_scratch, &tid, &s, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int on_openat_exit(struct trace_event_raw_sys_exit *ctx) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct openscratch *s = bpf_map_lookup_elem(&open_scratch, &tid);
    if (!s) return 0;

    long ret = ctx->ret;                   /* the new fd, or -errno */
    if (ret < 0) { bpf_map_delete_elem(&open_scratch, &tid); return 0; }

    struct fdinfo fi = {};
    bpf_probe_read_user_str(fi.path, sizeof(fi.path), (const void *)s->fname_ptr);
    if (!under_target(fi.path)) { bpf_map_delete_elem(&open_scratch, &tid); return 0; }

    fi.is_append = (s->flags & O_APPEND) ? 1 : 0;
    __u64 tgid = bpf_get_current_pid_tgid() >> 32;
    __u64 key  = (tgid << 32) | (__u32)ret;
    bpf_map_update_elem(&fd_paths, &key, &fi, BPF_ANY);
    bpf_map_delete_elem(&open_scratch, &tid);
    return 0;
}

/* ---- read / write on a tracked fd ------------------------------------- */

static __always_inline struct fdinfo *lookup_fd(int fd) {
    __u64 tgid = bpf_get_current_pid_tgid() >> 32;
    __u64 key  = (tgid << 32) | (__u32)fd;
    return bpf_map_lookup_elem(&fd_paths, &key);
}

SEC("tp/syscalls/sys_enter_read")
int on_read(struct trace_event_raw_sys_enter *ctx) {
    struct fdinfo *fi = lookup_fd((int)ctx->args[0]);
    if (fi) emit(OP_READ, fi);
    return 0;
}

SEC("tp/syscalls/sys_enter_pread64")
int on_pread(struct trace_event_raw_sys_enter *ctx) {
    struct fdinfo *fi = lookup_fd((int)ctx->args[0]);
    if (fi) emit(OP_READ, fi);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int on_write(struct trace_event_raw_sys_enter *ctx) {
    struct fdinfo *fi = lookup_fd((int)ctx->args[0]);
    if (fi) emit(fi->is_append ? OP_APPEND : OP_WRITE, fi);
    return 0;
}

SEC("tp/syscalls/sys_enter_pwrite64")
int on_pwrite(struct trace_event_raw_sys_enter *ctx) {
    struct fdinfo *fi = lookup_fd((int)ctx->args[0]);
    if (fi) emit(OP_WRITE, fi);           /* pwrite = positioned overwrite */
    return 0;
}

/* housekeeping: when a fd is closed, forget it so numbers don't leak across
 * reuse. Not strictly required for the study but keeps the map tidy. */
SEC("tp/syscalls/sys_enter_close")
int on_close(struct trace_event_raw_sys_enter *ctx) {
    __u64 tgid = bpf_get_current_pid_tgid() >> 32;
    __u64 key  = (tgid << 32) | (__u32)ctx->args[0];
    bpf_map_delete_elem(&fd_paths, &key);
    return 0;
}