// syscall_mon.bpf.c — the "conventional syscall open" monitor (baseline).
//
// do_sys_openat2() is the kernel service routine BOTH the openat(2) and
// openat2(2) syscalls run through. io_uring's opens call do_filp_open()
// directly and NEVER reach do_sys_openat2, so this monitor catches ordinary
// syscall opens and structurally cannot see io_uring — the visibility gap the
// study measures. Same coverage as a syscall tracepoint.
//
// We attach with fentry rather than a syscall tracepoint because perf-based
// tracepoint attach does not DELIVER events on this kernel (it attaches but the
// program never runs); fentry is reliable here — it is the same mechanism the
// working LSM monitor uses. 'filename' is a __user pointer; 'how' is kernel
// memory already copied in from userspace, so its flags read with CO-RE.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "monitor.bpf.h"

char LICENSE[] SEC("license") = "GPL";
#define O_ACCMODE 00000003

static __always_inline int op_from_flags(__u64 flags) {
    if ((flags & O_ACCMODE) == 0) return EVT_READ;
    if (flags & O_APPEND)         return EVT_APPEND;
    return EVT_WRITE;
}

SEC("fentry/do_sys_openat2")
int BPF_PROG(on_open, int dfd, const char *filename, struct open_how *how) {
    char path[MAX_PATH_LEN] = {};
    bpf_probe_read_user_str(path, sizeof(path), filename);
    if (!under_target(path)) return 0;
    __u64 flags = BPF_CORE_READ(how, flags);   /* 'how' is kernel memory here */
    emit(op_from_flags(flags), path);
    return 0;
}
