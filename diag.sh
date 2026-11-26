#!/usr/bin/env bash
set -u; cd "$(dirname "$0")"
TRACE=/sys/kernel/debug/tracing; [ -d "$TRACE" ] || TRACE=/sys/kernel/tracing
sudo -v
OUT=/tmp/iouring-study; mkdir -p "$OUT"
CSV="$OUT/diag.csv"; GT="$OUT/diag_gt.csv"

echo "===== 1. decoys present + which filesystem ====="
ls -l /var/tmp/iouring-study/targets/ 2>&1
findmnt -n -o SOURCE,FSTYPE --target /var/tmp/iouring-study/targets 2>&1

echo "===== 2. clear kernel trace buffer ====="
sudo bash -c "echo > $TRACE/trace"
sudo rm -f "$CSV" "$CSV.ready" "$GT"

echo "===== 3. attach monitor ====="
sudo timeout 20 ./monitor syscall_mon.bpf.o syscall "$CSV" &
for i in $(seq 1 60); do [ -f "$CSV.ready" ] && break; sleep 0.25; done
echo "attached? ready=$([ -f "$CSV.ready" ] && echo yes || echo NO)"

echo "===== 4. run workload (syscall mode) ====="
./workload --mode syscall --gt "$GT"
sleep 1

echo "===== 5. the hook's own printk lines (TRUTH about the path it read) ====="
sudo grep -F "bpf_trace_printk" "$TRACE/trace" | head -40
echo "   (if these show the decoy paths -> hook+read WORK, bug is downstream)"

echo "===== 6. stop monitor, count CSV events ====="
sudo pkill -INT -f "monitor syscall_mon.bpf.o"; wait 2>/dev/null
echo "CSV rows (minus header): $(( $(wc -l < "$CSV" 2>/dev/null || echo 1) - 1 ))"

echo "===== 7. paths the workload actually opened (compare to the baked prefix) ====="
echo "baked prefix in monitor: /var/tmp/iouring-study/targets/"
cut -d, -f5 "$GT" 2>/dev/null | sort -u
