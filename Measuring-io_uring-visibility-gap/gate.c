// Without --enforce it runs in AUDIT mode: nothing is blocked, but every
// io_uring_setup() from a non-allowlisted binary is logged as would_deny.
// That's the compatibility experiment (what would this policy break?).
// With --enforce, non-allowlisted callers get -EPERM.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "gate_event.h"

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static FILE *out;

/* Userspace st_dev and the kernel's sb->s_dev use different bit layouts.
 * The kernel's internal dev_t is MKDEV(ma, mi) = (ma << 20) | mi.
 * Convert, or no allowlist key would ever match. */
static __u32 kdev(dev_t d) { return ((__u32)major(d) << 20) | (__u32)minor(d); }

/* Does the running kernel have the LSM hook, and is BPF in the active LSM list? */
static int have_lsm_hook(void) {
    int sym = 0, lsm = 0;
    char line[512];
    FILE *f = fopen("/proc/kallsyms", "r");
    if (f) {
        while (fgets(line, sizeof line, f))
            if (strstr(line, " bpf_lsm_uring_allowed\n")) { sym = 1; break; }
        fclose(f);
    }
    f = fopen("/sys/kernel/security/lsm", "r");
    if (f) {
        if (fgets(line, sizeof line, f)) {
            /* the list is comma-separated, e.g. "lockdown,capability,...,bpf" */
            char *tok = strtok(line, ",\n");
            for (; tok; tok = strtok(NULL, ",\n"))
                if (!strcmp(tok, "bpf")) lsm = 1;
        }
        fclose(f);
    }
    return sym && lsm;
}

/* CSV-safe copy of comm (no commas/quotes/newlines) */
static void clean(char *dst, const char *src, size_t n) {
    size_t i = 0;
    for (; i + 1 < n && src[i]; i++)
        dst[i] = (src[i] == ',' || src[i] == '"' || src[i] == '\n') ? '_' : src[i];
    dst[i] = 0;
}

static int on_event(void *ctx, void *data, size_t len) {
    (void)ctx;
    if (len < sizeof(struct gate_event)) return 0;
    const struct gate_event *e = data;

    /* exe path, best effort: the process may already have exited. The BPF
     * side can't call bpf_d_path from this hook (not a sleepable hook), so we
     * resolve it here from /proc. dev/ino are the authoritative identity. */
    char link[64], exe[PATH_MAX] = "?";
    snprintf(link, sizeof link, "/proc/%u/exe", e->tgid);
    ssize_t n = readlink(link, exe, sizeof exe - 1);
    if (n > 0) exe[n] = 0; else strcpy(exe, "?");

    char comm[GATE_COMM_LEN + 1];
    clean(comm, e->comm, sizeof comm);

    fprintf(out, "%llu,%u,%u,%s,%s,%u,%llu,\"%s\"\n",
            (unsigned long long)e->ts_ns, e->tgid, e->tid, comm,
            e->verdict == VERDICT_DENIED ? "denied" : "would_deny",
            e->exe.dev, (unsigned long long)e->exe.ino, exe);
    fflush(out);
    fprintf(stderr, "[gate] %s: pid=%u comm=%s exe=%s\n",
            e->verdict == VERDICT_DENIED ? "DENIED" : "would deny",
            e->tgid, comm, exe);
    return 0;
}

static void usage(const char *p) {
    fprintf(stderr,
        "usage: sudo %s [--enforce] [--allow PATH]... [--csv FILE]\n"
        "                 [--attach auto|lsm|fmod] [--obj gate.bpf.o]\n", p);
}

int main(int argc, char **argv) {
    const char *obj_path = "gate.bpf.o";
    const char *csv = "/tmp/iouring-study/gate_events.csv";
    const char *attach = "auto";
    const char *allow[256];
    int nallow = 0, enforce = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--enforce")) enforce = 1;
        else if (!strcmp(argv[i], "--allow") && i + 1 < argc && nallow < 256) allow[nallow++] = argv[++i];
        else if (!strcmp(argv[i], "--csv") && i + 1 < argc) csv = argv[++i];
        else if (!strcmp(argv[i], "--attach") && i + 1 < argc) attach = argv[++i];
        else if (!strcmp(argv[i], "--obj") && i + 1 < argc) obj_path = argv[++i];
        else { usage(argv[0]); return 2; }
    }

    /* pick the attach point */
    int use_lsm;
    if (!strcmp(attach, "lsm")) use_lsm = 1;
    else if (!strcmp(attach, "fmod")) use_lsm = 0;
    else if (!strcmp(attach, "auto")) use_lsm = have_lsm_hook();
    else { usage(argv[0]); return 2; }

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) { fprintf(stderr, "open %s: %s\n", obj_path, strerror(errno)); return 1; }

    struct bpf_program *p_lsm  = bpf_object__find_program_by_name(obj, "gate_lsm");
    struct bpf_program *p_fmod = bpf_object__find_program_by_name(obj, "gate_fmod");
    if (!p_lsm) { fprintf(stderr, "gate_lsm program missing from %s\n", obj_path); return 1; }
    if (!use_lsm && !p_fmod) { fprintf(stderr, "no fmod_ret program for this arch\n"); return 1; }

    /* Load only the program we'll attach. A disabled program isn't verified
     * or resolved against kernel BTF, so the fmod path still loads on a
     * kernel that has no uring_allowed hook at all. */
    bpf_program__set_autoload(p_lsm, use_lsm);
    if (p_fmod) bpf_program__set_autoload(p_fmod, !use_lsm);

    if (bpf_object__load(obj)) {
        fprintf(stderr, "load failed (%s). Run as root; check `uname -r` "
                        "and that BPF-LSM is enabled if using lsm.\n", strerror(errno));
        return 1;
    }

    /* config: enforce flag */
    int cfg_fd = bpf_object__find_map_fd_by_name(obj, "cfg");
    __u32 k = CFG_ENFORCE, v = enforce;
    if (bpf_map_update_elem(cfg_fd, &k, &v, BPF_ANY)) { perror("cfg"); return 1; }

    /* allowlist: stat each path and insert its (kernel dev, inode) */
    int allow_fd = bpf_object__find_map_fd_by_name(obj, "allow");
    for (int i = 0; i < nallow; i++) {
        char real[PATH_MAX];
        struct stat st;
        if (!realpath(allow[i], real) || stat(real, &st)) {
            fprintf(stderr, "allow %s: %s\n", allow[i], strerror(errno)); return 1;
        }
        struct exe_key key = { .dev = kdev(st.st_dev), ._pad = 0, .ino = st.st_ino };
        __u8 one = 1;
        if (bpf_map_update_elem(allow_fd, &key, &one, BPF_ANY)) { perror("allow insert"); return 1; }
        fprintf(stderr, "[gate] allow %s (dev=%u ino=%llu)\n",
                real, key.dev, (unsigned long long)key.ino);
    }

    struct bpf_link *link = bpf_program__attach(use_lsm ? p_lsm : p_fmod);
    if (!link) { fprintf(stderr, "attach failed: %s\n", strerror(errno)); return 1; }

    out = fopen(csv, "w");
    if (!out) { perror(csv); return 1; }
    fprintf(out, "ts_ns,tgid,tid,comm,verdict,exe_dev,exe_ino,exe_path\n");
    fflush(out);

    struct ring_buffer *rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "rb"),
                                              on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring buffer setup failed\n"); return 1; }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    fprintf(stderr, "[gate] active: attach=%s mode=%s allowlist=%d entries -> %s\n",
            use_lsm ? "lsm/uring_allowed" : "fmod_ret", enforce ? "ENFORCE" : "audit",
            nallow, csv);

    while (!stop) {
        int r = ring_buffer__poll(rb, 200 /* ms */);
        if (r < 0 && r != -EINTR) { fprintf(stderr, "poll: %d\n", r); break; }
    }
    ring_buffer__consume(rb);   /* drain anything left */

    /* counters */
    int st_fd = bpf_object__find_map_fd_by_name(obj, "stats");
    const char *names[] = { "allowed", "denied", "would_deny", "ringbuf_drops" };
    fprintf(stderr, "\n[gate] setup calls:");
    for (__u32 i = 0; i < 4; i++) {
        __u64 c = 0;
        bpf_map_lookup_elem(st_fd, &i, &c);
        fprintf(stderr, " %s=%llu", names[i], (unsigned long long)c);
    }
    fprintf(stderr, "\n");

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    fclose(out);
    return 0;
}