#!/usr/bin/env bash
set -u; cd "$(dirname "$0")"
OUT=/tmp/iouring-study; mkdir -p "$OUT"
TRACE=/sys/kernel/tracing; [ -d "$TRACE" ] || TRACE=/sys/kernel/debug/tracing
sudo -v
sudo sh -c "echo > $TRACE/trace"
sudo rm -f "$OUT"/sc.csv "$OUT"/sc.csv.ready; rm -f "$OUT"/ground_truth.csv
sudo timeout 8 ./monitor syscall_mon.bpf.o syscall "$OUT/sc.csv" &
for i in $(seq 1 40); do [ -f "$OUT"/sc.csv.ready ] && break; sleep 0.25; done
echo ">> monitor ready; running cached syscall workload"
./workload --mode syscall
sleep 1
echo "===== openat hook saw (decoy opens only) ====="
sudo grep -aE 'OENTER|OEXIT' "$TRACE/trace" | grep -a decoy | head -30
echo "===== syscall CSV event count ====="
echo $(( $(wc -l < "$OUT"/sc.csv) - 1 ))
wait
