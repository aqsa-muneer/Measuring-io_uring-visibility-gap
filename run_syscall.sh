#!/usr/bin/env bash
set -u; cd "$(dirname "$0")"
OUT=/tmp/iouring-study; ISO="$OUT/iso"; mkdir -p "$ISO"
sudo -v
CSV="$OUT/syscall_mon.csv"; GT="$OUT/ground_truth.csv"
sudo rm -f "$CSV" "$CSV.ready"; rm -f "$GT"
sudo timeout 30 ./monitor syscall_mon.bpf.o syscall "$CSV" &
for i in $(seq 1 60); do [ -f "$CSV.ready" ] && break; sleep 0.25; done
echo ">> attached; syscall-mode workload"
./workload --mode syscall ; sleep 2
sudo pkill -INT -f "monitor syscall_mon.bpf.o"; wait 2>/dev/null
echo ">> syscall events captured RIGHT NOW: $(( $(wc -l < "$CSV") - 1 ))"
echo ">> monitor detached; filling ground truth with io_uring modes"
./workload --mode uring ; ./workload --mode sqpoll
cp "$GT" "$ISO/syscall_gt.csv"; cp "$CSV" "$ISO/syscall_mon.csv"
python3 score.py --gt "$ISO/syscall_gt.csv" --mon "$ISO/syscall_mon.csv" \
    --outdir "$ISO/out_syscall" 2>&1 | sed -n '/Recall/,/wrote/p'
