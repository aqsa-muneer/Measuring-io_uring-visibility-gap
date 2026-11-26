#!/usr/bin/env bash
set -e; cd "$(dirname "$0")"

# 1) corrected two-hook syscall monitor (covers openat AND openat2, no printk)
cat > syscall_mon.bpf.c << 'CEOF'
// syscall_mon.bpf.c — the "conventional syscall-tracepoint monitor" (baseline).
// Watches the kernel's syscall-ENTER tracepoints for file opens and reports any
// open whose path is under the decoy dir. io_uring issues its opens through the
// io_uring submission path, NOT these syscalls, so these tracepoints never fire
// for io_uring ops — exactly the visibility gap the study measures.
//
// TWO hooks on purpose: glibc's openat() is implemented here via the openat2(2)
// syscall, which raises sys_enter_openat2, not sys_enter_openat. A monitor that
// watches only sys_enter_openat sees nothing. A faithful syscall-tracepoint
// monitor must cover both entry points.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "monitor.bpf.h"

char LICENSE[] SEC("license") = "GPL";
#define O_ACCMODE 00000003

/* no write bits => read; O_APPEND => append; else overwriting write */
static __always_inline int op_from_flags(__u64 flags) {
    if ((flags & O_ACCMODE) == 0) return EVT_READ;
    if (flags & O_APPEND)         return EVT_APPEND;
    return EVT_WRITE;
}

/* shared tail: read user path, keep only decoy-dir paths, emit one event */
static __always_inline int report_open(const void *filename_uptr, __u64 flags) {
    char path[MAX_PATH_LEN] = {};
    bpf_probe_read_user_str(path, sizeof(path), filename_uptr);
    if (!under_target(path)) return 0;
    emit(op_from_flags(flags), path);
    return 0;
}

/* openat(dfd, filename, flags, mode): args[1]=filename, args[2]=flags */
SEC("tp/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx) {
    return report_open((const void *)ctx->args[1],
                       (__u64)(unsigned int)ctx->args[2]);
}

/* openat2(dfd, filename, how, usize): args[1]=filename, flags are how->flags */
SEC("tp/syscalls/sys_enter_openat2")
int on_openat2(struct trace_event_raw_sys_enter *ctx) {
    struct open_how how = {};
    bpf_probe_read_user(&how, sizeof(how), (const void *)ctx->args[2]);
    return report_open((const void *)ctx->args[1], how.flags);
}
CEOF
echo ">> wrote syscall_mon.bpf.c"

# 2) rebuild just this object
rm -f syscall_mon.bpf.o
make syscall_mon.bpf.o
echo ">> sections in the rebuilt object (expect BOTH openat and openat2):"
llvm-objdump -h syscall_mon.bpf.o 2>/dev/null | grep -E "sys_enter_openat" || true

# 3) prove which syscall glibc uses to open a decoy (evidence for the report)
echo ">> syscall the workload actually issues:"
strace -f -e trace=openat,openat2 ./workload --mode syscall \
    --gt /tmp/iouring-study/strace_gt.csv 2>&1 \
  | grep -i decoy | grep -oE "openat2?\(" | sort | uniq -c || true

# 4) re-run capture
sudo -v
OUT=/tmp/iouring-study; mkdir -p "$OUT"; CSV="$OUT/fix.csv"; GT="$OUT/fix_gt.csv"
sudo rm -f "$CSV" "$CSV.ready" "$GT"
sudo timeout 20 ./monitor syscall_mon.bpf.o syscall "$CSV" &
for i in $(seq 1 60); do [ -f "$CSV.ready" ] && break; sleep 0.25; done
./workload --mode syscall --gt "$GT"; sleep 1
sudo pkill -INT -f "monitor syscall_mon.bpf.o"; wait 2>/dev/null
echo ">> events captured: $(( $(wc -l < "$CSV") - 1 ))   (expect 9)"
column -t -s, "$CSV" | head
