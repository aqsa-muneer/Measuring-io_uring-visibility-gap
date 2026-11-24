/*
 * block_mon.bpf.c — block-layer tracepoint monitor (kernel side).
 *
 * The weakest monitor, and that's the point. It hooks block_rq_issue, which
 * fires when a request goes to the device. It sees device/sector/size and the
 * read-vs-write flag — but NO path and NO reliable PID:
 *
 *   - Cached reads never reach the block layer (served from page cache), so it
 *     sees nothing for them. Use the workload's O_DIRECT variant, on an
 *     otherwise-idle system, or this monitor has nothing to observe.
 *   - Buffered writes are flushed later by a kworker/flush thread, so the
 *     task issuing the request is NOT the workload — the PID is wrong.
 *   - O_DIRECT writes/reads ARE issued in the submitting task's context, so
 *     there the PID can be right. That cached-vs-direct difference is itself a
 *     finding worth reporting.
 *
 * We emit op (from rwbs) with an empty path and the current PID. The scorer's
 * path-free bars then show block as "saw a disk op of this type" (op_recall)
 * but usually "wrong PID" (low pid_recall) and "no path" (recall ~0).
 *
 * NOISE WARNING: there is no path here to filter on, so this fires for ALL
 * disk I/O on the machine. Run block experiments on a quiet VM so the only
 * traffic is the workload's; otherwise the time-join will pick up unrelated
 * I/O. (A device-id filter can be added if the decoys live on a known disk.)
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "monitor.bpf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tp/block/block_rq_issue")
int on_block_issue(struct trace_event_raw_block_rq_issue *ctx) {
    /* rwbs is a short text flag field: 'R'ead, 'W'rite, 'F'lush, 'D'iscard */
    char c = ctx->rwbs[0];

    int op;
    if (c == 'R')      op = OP_READ;
    else if (c == 'W') op = OP_WRITE;   /* append indistinguishable here */
    else               return 0;        /* flush/discard/etc — ignore */

    char nopath[MAX_PATH_LEN] = {};
    emit(op, nopath);
    return 0;
}