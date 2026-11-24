/*
 * monitor.c — ONE generic userspace loader for every monitor.
 *
 * The three monitors differ only in their .bpf.c; the loader logic (load,
 * attach all programs, drain the ring buffer to CSV, report drops) is
 * identical. So instead of three near-copies we load the .bpf.o by name and
 * let libbpf pick each program's attach type from its SEC() string
 * ("tp/..." for the syscall monitor, "lsm/..." for this one, etc.).
 *
 *   usage: sudo ./monitor <program.bpf.o> <source_label> [out.csv]
 *   e.g.   sudo ./monitor lsm_mon.bpf.o lsm /tmp/iouring-study/lsm_mon.csv
 *
 * <source_label> is written into every row's "source" column, so the scorer
 * can tell which monitor produced which detections.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "event.h"

static volatile sig_atomic_t stop;
static void on_sigint(int s) { (void)s; stop = 1; }

static const char *op_str(int op) {
    switch (op) { case OP_READ: return "read";
                  case OP_WRITE: return "write";
                  case OP_APPEND: return "append";
                  default: return "?"; }
}

static FILE *out;
static const char *source;        /* the monitor label for the CSV */
static unsigned long n_written;

static int on_event(void *ctx, void *data, size_t len) {
    (void)ctx; (void)len;
    const struct event *e = data;
    fprintf(out, "%llu,%s,%u,%u,%s,%s,%s\n",
            e->ts_ns, source, e->tgid, e->tid, e->comm, op_str(e->op), e->path);
    n_written++;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <program.bpf.o> <source_label> [out.csv]\n", argv[0]);
        return 2;
    }
    const char *objpath = argv[1];
    source               = argv[2];
    const char *csv      = (argc > 3) ? argv[3] : "/tmp/iouring-study/monitor.csv";

    out = fopen(csv, "w");
    if (!out) { perror("open csv"); return 1; }
    fprintf(out, "ts_ns,source,tgid,tid,comm,op,path\n");

    /* 1) open + load the compiled BPF object */
    struct bpf_object *obj = bpf_object__open_file(objpath, NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "open %s failed\n", objpath); return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "load failed (need root; CONFIG_BPF_LSM + lsm=bpf for the LSM monitor)\n");
        bpf_object__close(obj); return 1;
    }

    /* 2) attach every program; libbpf picks the type from each SEC() string */
    struct bpf_program *prog;
    int attached = 0;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link || libbpf_get_error(link))
            fprintf(stderr, "warn: attach failed for %s\n", bpf_program__name(prog));
        else
            attached++;
    }
    if (!attached) { fprintf(stderr, "nothing attached\n"); bpf_object__close(obj); return 1; }

    /* 3) find the shared maps by name and start draining the ring buffer */
    struct bpf_map *rb_map    = bpf_object__find_map_by_name(obj, "rb");
    struct bpf_map *drops_map = bpf_object__find_map_by_name(obj, "drops");
    if (!rb_map) { fprintf(stderr, "no 'rb' map in object\n"); bpf_object__close(obj); return 1; }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(rb_map), on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer__new failed\n"); bpf_object__close(obj); return 1; }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    fprintf(stderr, "%s monitor running (%d progs) — run the workload, then Ctrl-C.\n",
            source, attached);

    while (!stop) {
        int err = ring_buffer__poll(rb, 200 /* ms */);
        if (err < 0 && err != -EINTR) { fprintf(stderr, "poll err %d\n", err); break; }
    }
    fflush(out);

    /* 4) report the kernel-side drop counter next to the event count */
    unsigned long long dropped = 0; unsigned int z = 0;
    if (drops_map)
        bpf_map__lookup_elem(drops_map, &z, sizeof(z), &dropped, sizeof(dropped), 0);
    fprintf(stderr, "\n[%s] events written: %lu   dropped (ringbuf full): %llu\n",
            source, n_written, dropped);

    ring_buffer__free(rb);
    bpf_object__close(obj);
    fclose(out);
    return 0;
}