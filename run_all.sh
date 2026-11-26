#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
OUT=/tmp/iouring-study
DUR=${1:-20}; shift || true
WL="$*"
mkdir -p "$OUT"
rm -f "$OUT"/ground_truth.csv
sudo -v
sudo rm -f "$OUT"/*_mon.csv "$OUT"/*_mon.csv.ready
for spec in \
    "syscall_mon.bpf.o syscall" \
    "lsm_mon.bpf.o     lsm" \
    "uring_tp_mon.bpf.o uring_tp" \
    "block_mon.bpf.o   block"; do
    set -- $spec
    sudo timeout "$DUR" ./monitor "$1" "$2" "$OUT/$2_mon.csv" &
done
echo ">> waiting for all 4 monitors to attach ..."
n=0
for i in $(seq 1 60); do
    n=$(ls "$OUT"/*_mon.csv.ready 2>/dev/null | wc -l)
    [ "$n" -ge 4 ] && break
    sleep 0.5
done
echo ">> $n/4 attached; running workload (uring, sqpoll, syscall)  flags: ${WL:-none}"
./workload --mode uring   $WL ; sleep 1
./workload --mode sqpoll  $WL ; sleep 1
./workload --mode syscall $WL
wait
echo; echo ">> done. CSVs:"; ls -l "$OUT"/*.csv
