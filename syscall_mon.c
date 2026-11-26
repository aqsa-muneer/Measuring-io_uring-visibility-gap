// Loads the BPF object, drains the ring buffer, and writes one CSV row per detection
// prints how many events it wrote and how many the kernel had to 
// drop (ring buffer full). That drop count is the "dropped events" metric for this monitor
// Run it, THEN run the workload in another shell, THEN Ctrl-C here.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "event.h"
#include "syscall_mon.skel.h"

static volatile sig_atomic_t stop;
static void on_sigint(int s) { (void)s; stop = 1; }

static const char *op_str(int op) {
    switch (op) { case EVT_READ: return "read";
                  case EVT_WRITE: return "write";
                  case EVT_APPEND: return "append";
                  default: return "?"; }
}

static FILE *out;
static unsigned long n_written;

/* ring-buffer callback: one record per detection */
static int on_event(void *ctx, void *data, size_t len) {
    (void)ctx; (void)len;
    const struct event *e = data;
    /* source is fixed for this monitor; the scorer uses it to tell monitors apart */
    fprintf(out, "%llu,syscall,%u,%u,%s,%s,%s\n",
            e->ts_ns, e->tgid, e->tid, e->comm, op_str(e->op), e->path);
    n_written++;
    return 0;
}

int main(int argc, char **argv) {
    const char *csv = (argc > 1) ? argv[1] : "/tmp/iouring-study/syscall_mon.csv";

    out = fopen(csv, "w");
    if (!out) { perror("open csv"); return 1; }
    fprintf(out, "ts_ns,source,tgid,tid,comm,op,path\n");

    struct syscall_mon_bpf *skel = syscall_mon_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "failed to open/load BPF (need root; CONFIG_* ok?)\n"); return 1; }
    if (syscall_mon_bpf__attach(skel)) { fprintf(stderr, "attach failed\n"); goto cleanup; }

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.rb), on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer__new failed\n"); goto cleanup; }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    fprintf(stderr, "syscall monitor running — run the workload, then Ctrl-C.\n");

    while (!stop) {
        int err = ring_buffer__poll(rb, 200 /* ms */);
        if (err < 0 && err != -EINTR) { fprintf(stderr, "poll err %d\n", err); break; }
    }
    fflush(out);

    /* read the kernel-side drop counter */
    __u64 dropped = 0; __u32 z = 0;
    bpf_map__lookup_elem(skel->maps.drops, &z, sizeof(z), &dropped, sizeof(dropped), 0);

    fprintf(stderr, "\nevents written: %lu   dropped (ringbuf full): %llu\n",
            n_written, dropped);
    ring_buffer__free(rb);
cleanup:
    syscall_mon_bpf__destroy(skel);
    fclose(out);
    return 0;
}