# Flat-layout Makefile — all sources in ONE directory.
# Builds: the workload generator, the two cost benchmarks, the four eBPF
# detection monitors + their loader, and the io_uring_setup gate (BPF + loader).
#
# VM deps (once):
#   sudo apt install -y liburing-dev clang llvm libbpf-dev \
#        linux-tools-$(uname -r) libelf-dev zlib1g-dev
#
# Usage:
#   make            # build everything
#   make clean      # remove build outputs

CLANG   := clang
BPFTOOL := bpftool

# map CPU arch to the __TARGET_ARCH_* that bpf_tracing.h wants
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/armv7l/arm/')

CFLAGS     := -g -O2 -Wall -I.
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.

# the four detection monitors (all share event.h + monitor.bpf.h)
BPFOBJS := syscall_mon.bpf.o lsm_mon.bpf.o uring_tp_mon.bpf.o block_mon.bpf.o

.PHONY: all clean
all: workload bench setup_bench flood monitor $(BPFOBJS) gate gate.bpf.o

# ---- workload generator + cost benchmarks (plain C + liburing) ----
workload: workload.c
	gcc -O2 -Wall -Wextra -g -o workload workload.c -luring

bench: bench.c
	gcc -O2 -Wall -Wextra -g -o bench bench.c -luring

# gate cost microbenchmark: times raw io_uring_setup(), no liburing needed
setup_bench: setup_bench.c
	gcc -O2 -Wall -Wextra -g -o setup_bench setup_bench.c

# flood-evasion stress tool (multithreaded io_uring; pthreads + liburing)
flood: flood.c
	gcc -O2 -Wall -Wextra -g -o flood flood.c -luring -lpthread

# ---- running kernel's types, for CO-RE portability ----
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# ---- detection monitors: each <name>.bpf.c -> <name>.bpf.o ----
$(BPFOBJS): %.bpf.o: %.bpf.c vmlinux.h event.h monitor.bpf.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# ---- the generic loader used for every detection monitor ----
monitor: monitor.c event.h
	$(CLANG) $(CFLAGS) monitor.c -o monitor -lbpf -lelf -lz

# ---- the io_uring_setup gate: BPF object + its own loader ----
# gate.bpf.c uses gate_event.h (not event.h/monitor.bpf.h), so it has its
# own rule rather than the $(BPFOBJS) pattern.
gate.bpf.o: gate.bpf.c vmlinux.h gate_event.h
	$(CLANG) $(BPF_CFLAGS) -c gate.bpf.c -o gate.bpf.o

gate: gate.c gate_event.h
	$(CLANG) $(CFLAGS) gate.c -o gate -lbpf -lelf -lz

clean:
	rm -f workload bench setup_bench flood monitor gate $(BPFOBJS) gate.bpf.o vmlinux.h
