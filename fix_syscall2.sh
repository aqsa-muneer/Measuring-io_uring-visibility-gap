#!/usr/bin/env bash
set -e; cd "$(dirname "$0")"

cat > syscall_mon.bpf.c << 'CEOF'
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
CEOF
echo ">> wrote fentry-based syscall_mon.bpf.c"
rm -f syscall_mon.bpf.o
make syscall_mon.bpf.o
echo ">> section (expect fentry/do_sys_openat2):"
llvm-objdump -h syscall_mon.bpf.o 2>/dev/null | grep -Ei "fentry|openat2" || true

# cross-check for the report: does the raw tracepoint fire system-wide at all?
echo ">> bpftrace cross-check (did the tracepoint itself fire for 'workload'?):"
if command -v bpftrace >/dev/null; then
  sudo timeout 7 bpftrace -e 'tracepoint:syscalls:sys_enter_openat /comm=="workload"/ { @c=count(); }' &
  BT=$!; sleep 1
  ./workload --mode syscall --gt /tmp/iouring-study/bt_gt.csv >/dev/null 2>&1 || true
  sleep 1; sudo kill -INT $BT 2>/dev/null || true; wait $BT 2>/dev/null || true
else
  echo "   (bpftrace not installed — skipping; not needed for the fix)"
fi

# run the fentry monitor
sudo -v
OUT=/tmp/iouring-study; mkdir -p "$OUT"; CSV="$OUT/fix.csv"; GT="$OUT/fix_gt.csv"
sudo rm -f "$CSV" "$CSV.ready" "$GT"
sudo timeout 20 ./monitor syscall_mon.bpf.o syscall "$CSV" &
for i in $(seq 1 60); do [ -f "$CSV.ready" ] && break; sleep 0.25; done
./workload --mode syscall --gt "$GT"; sleep 1
sudo pkill -INT -f "monitor syscall_mon.bpf.o"; wait 2>/dev/null
echo ">> events captured: $(( $(wc -l < "$CSV") - 1 ))   (expect 9)"
column -t -s, "$CSV" | head
