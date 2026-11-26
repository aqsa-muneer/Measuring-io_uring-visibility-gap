// decides who may create an io_uring instance in the first place. 
// A process whose executable is not on the allowlist gets
// -EPERM from io_uring_setup(), so it either fails or has to fall back to ordinary syscalls

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "gate_event.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

/* allowlist: exe identity -> 1. Filled by the loader (gate --allow PATH). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct exe_key);
    __type(value, __u8);
} allow SEC(".maps");

/* runtime config (enforce flag). An ARRAY map instead of a const volatile
 * global so the loader can set it after load and you could flip it live. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CFG_NSLOTS);
    __type(key, __u32);
    __type(value, __u32);
} cfg SEC(".maps");

/* decisions for non-allowlisted callers go here; allowed calls are NOT
 * logged, so the allowed fast path stays cheap (matters for the cost test). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);   /* 256 KiB */
} rb SEC(".maps");

/* counters: [0] allowed, [1] denied, [2] would-deny, [3] ringbuf drops */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 slot) {
    __u64 *v = bpf_map_lookup_elem(&stats, &slot);
    if (v) __sync_fetch_and_add(v, 1);
}

/* Shared decision logic. Returns 0 (allow) or -EPERM (deny). */
static __always_inline int decide(void) {
    struct task_struct *t = bpf_get_current_task_btf();
    struct exe_key k = {};

    /* mm->exe_file is the file the process was exec'd from. Each read is
     * CO-RE relocated, and a NULL anywhere along the chain reads back as 0,
     * which simply won't be on the allowlist. */
    struct file *exe = BPF_CORE_READ(t, mm, exe_file);
    if (exe) {
        k.dev = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);
        k.ino = BPF_CORE_READ(exe, f_inode, i_ino);
    }

    if (bpf_map_lookup_elem(&allow, &k)) {
        bump(0);
        return 0;                                   /* allowlisted: let it through */
    }

    __u32 z = CFG_ENFORCE;
    __u32 *enf = bpf_map_lookup_elem(&cfg, &z);
    int enforce = enf && *enf;
    bump(enforce ? 1 : 2);

    /* record the decision — this is high-signal telemetry on its own:
     * an unknown binary trying to open a ring is worth an alert */
    struct gate_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        __u64 pt = bpf_get_current_pid_tgid();
        e->ts_ns   = bpf_ktime_get_ns();
        e->tgid    = pt >> 32;
        e->tid     = (__u32)pt;
        e->verdict = enforce ? VERDICT_DENIED : VERDICT_WOULD_DENY;
        e->_pad    = 0;
        e->exe     = k;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    } else {
        bump(3);
    }

    return enforce ? -EPERM : 0;
}

/* ---- attach point 1: the LSM hook (preferred) ---------------------------
 * The hook itself takes no arguments. BPF-LSM appends the return value of
 * the previous LSM in the chain as the last argument; if something earlier
 * already denied, we keep that decision instead of overriding it. */
SEC("lsm/uring_allowed")
int BPF_PROG(gate_lsm, int ret)
{
    if (ret)
        return ret;
    return decide();
}

/* ---- attach point 2: fmod_ret on the syscall (fallback, x86 only) --------
 * For fmod_ret: returning 0 lets the real syscall run; returning non-zero
 * skips it and makes that value the syscall's return value. */
#if defined(__TARGET_ARCH_x86)
SEC("fmod_ret/__x64_sys_io_uring_setup")
int BPF_PROG(gate_fmod, struct pt_regs *regs, int ret)
{
    return decide();
}
#elif defined(__TARGET_ARCH_arm64)
SEC("fmod_ret/__arm64_sys_io_uring_setup")
int BPF_PROG(gate_fmod, struct pt_regs *regs, int ret)
{
    return decide();
}
#endif