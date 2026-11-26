#!/usr/bin/env bash
set -u; cd "$(dirname "$0")"
OUT=/tmp/iouring-study; mkdir -p "$OUT"
TRACE=/sys/kernel/tracing; [ -d "$TRACE" ] || TRACE=/sys/kernel/debug/tracing
sudo -v
sudo sh -c "echo > $TRACE/trace"
sudo rm -f "$OUT"/sc.csv "$OUT"/sc.csv.ready; rm -f "$OUT"/ground_truth.csv
sudo timeout 8 ./monitor syscall_mon.bpf.o syscall "$OUT/sc.csv" &
for i in $(seq 1 40); do [ -f "$OUT"/sc.csv.ready ] && break; sleep 0.25; done
echo ">> ready; running workload"
./workload --mode syscall
sleep 1
echo "===== what the openat hooks saw for the workload ====="
sudo grep -aE 'WLOPEN' "$TRACE/trace" | head -30
echo "(empty above = openat/openat2 tracepoints never fired for the workload)"
wait
