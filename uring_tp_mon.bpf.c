/*
 * uring_tp_mon.bpf.c — io_uring's OWN tracepoints (kernel side).
 *
 * This is a comparison baseline, not a defense an attacker would face: it
 * answers "can you just watch io_uring directly?" It hooks the submit
 * tracepoint, which fires once per SQE and carries the OPCODE and the
 * submitting task — but NOT the target path and NOT the fd's file. So this
 * monitor can say "process P did an io_uring read" but cannot say WHICH file.
 *
 * That limitation is the finding: under a path-based security bar it recovers
 * ~0 (no path), yet it recovers the PID and the operation type perfectly. The
 * scorer's path-free bars (pid_recall / op_recall) are what show that.
 *
 * TRACEPOINT NAME NOTE: on 6.x kernels the submit tracepoint is
 * io_uring_submit_req. On older kernels it was io_uring_submit_sqe — if the
 * build can't find trace_event_raw_io_uring_submit_req in vmlinux.h, switch
 * both the SEC() name and the struct to the _sqe spelling.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "monitor.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* io_uring opcodes are stable ABI (include/uapi/linux/io_uring.h) */
#define IORING_OP_READV   1
#define IORING_OP_WRITEV  2
#define IORING_OP_READ    22
#define IORING_OP_WRITE   23

SEC("tp/io_uring/io_uring_submit_req")
int on_submit(struct trace_event_raw_io_uring_submit_req *ctx) {
    __u8 opcode = ctx->opcode;

    int op;
    if (opcode == IORING_OP_READ || opcode == IORING_OP_READV)
        op = OP_READ;
    else if (opcode == IORING_OP_WRITE || opcode == IORING_OP_WRITEV)
        op = OP_WRITE;                 /* can't tell append from write at submit */
    else
        return 0;                      /* openat/close/etc — not a scored op */

    /* no path available from this tracepoint — emit an empty one on purpose */
    char nopath[MAX_PATH_LEN] = {};
    emit(op, nopath);
    return 0;
}