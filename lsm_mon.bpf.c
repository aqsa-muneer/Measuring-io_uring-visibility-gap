#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "monitor.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* permission mask bits (from linux/fs.h; not in vmlinux.h) */
#define MAY_EXEC  0x1
#define MAY_WRITE 0x2
#define MAY_READ  0x4

/*
 * BPF_PROG unpacks the hook's typed arguments for us. The file_permission hook
 * signature is: int file_permission(struct file *file, int mask).
 * Returning 0 = "allow" — we only observe, never block.
 */
SEC("lsm/file_permission")
int BPF_PROG(on_file_perm, struct file *file, int mask) {
    char path[MAX_PATH_LEN] = {};

    /* resolve the path; bail if it can't be rendered */
    long r = bpf_d_path(&file->f_path, path, sizeof(path));
    if (r < 0) return 0;

    /* only our study's targets reach the ring buffer */
    if (!under_target(path)) return 0;

    int op;
    if (mask & MAY_WRITE) {
        /* append vs overwrite: read the open flags off the file */
        unsigned int fl = BPF_CORE_READ(file, f_flags);
        op = (fl & O_APPEND) ? OP_APPEND : OP_WRITE;
    } else if (mask & MAY_READ) {
        op = OP_READ;
    } else {
        return 0;                 /* exec/other — not an op we score */
    }

    emit(op, path);
    return 0;
}