#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "event.h"
static volatile sig_atomic_t stop;
static void on_sigint(int s) { (void)s; stop = 1; }
static const char *op_str(int op) {
    switch (op) { case EVT_READ: return "read"; case EVT_WRITE: return "write";
                  case EVT_APPEND: return "append"; default: return "?"; }
}
static FILE *out; static const char *source; static unsigned long n_written;
static int on_event(void *ctx, void *data, size_t len) {
    (void)ctx; (void)len; const struct event *e = data;
    fprintf(out, "%llu,%s,%u,%u,%s,%s,%s\n",
            e->ts_ns, source, e->tgid, e->tid, e->comm, op_str(e->op), e->path);
    fflush(out);                    /* write immediately, don't buffer to exit */
    n_written++; return 0;
}
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <prog.bpf.o> <label> [out.csv]\n", argv[0]); return 2; }
    const char *objpath = argv[1]; source = argv[2];
    const char *csv = (argc > 3) ? argv[3] : "/tmp/iouring-study/monitor.csv";
    out = fopen(csv, "w"); if (!out) { perror("open csv"); return 1; }
    fprintf(out, "ts_ns,source,tgid,tid,comm,op,path\n"); fflush(out);
    struct bpf_object *obj = bpf_object__open_file(objpath, NULL);
    if (!obj || libbpf_get_error(obj)) { fprintf(stderr, "open %s failed\n", objpath); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load failed\n"); bpf_object__close(obj); return 1; }
    struct bpf_program *prog; int attached = 0;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link || libbpf_get_error(link)) fprintf(stderr, "warn: attach failed %s\n", bpf_program__name(prog));
        else attached++;
    }
    if (!attached) { fprintf(stderr, "nothing attached\n"); bpf_object__close(obj); return 1; }
    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "rb");
    struct bpf_map *drops_map = bpf_object__find_map_by_name(obj, "drops");
    if (!rb_map) { fprintf(stderr, "no 'rb' map\n"); bpf_object__close(obj); return 1; }
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(rb_map), on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer__new failed\n"); bpf_object__close(obj); return 1; }
    signal(SIGINT, on_sigint); signal(SIGTERM, on_sigint);
    { char rp[1100]; snprintf(rp, sizeof rp, "%s.ready", csv);
      FILE *rf = fopen(rp, "w"); if (rf) { fputs("ready\n", rf); fclose(rf); } }
    fprintf(stderr, "%s monitor running (%d progs).\n", source, attached);
    while (!stop) { ring_buffer__consume(rb); usleep(50 * 1000); }
    ring_buffer__consume(rb);
    unsigned long long dropped = 0; unsigned int z = 0;
    if (drops_map) bpf_map__lookup_elem(drops_map, &z, sizeof(z), &dropped, sizeof(dropped), 0);
    fprintf(stderr, "\n[%s] events written: %lu   dropped (ringbuf full): %llu\n", source, n_written, dropped);
    ring_buffer__free(rb); bpf_object__close(obj); fclose(out); return 0;
}
