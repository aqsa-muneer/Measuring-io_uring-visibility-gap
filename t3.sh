#!/usr/bin/env bash
set -u; cd "$(dirname "$0")"
OUT=/tmp/iouring-study
sudo -v
sudo rm -f "$OUT"/t.csv "$OUT"/t.csv.ready; rm -f "$OUT"/tgt.csv
sudo timeout 30 ./monitor syscall_mon.bpf.o syscall "$OUT/t.csv" &
for i in $(seq 1 40); do [ -f "$OUT"/t.csv.ready ] && break; sleep 0.25; done
echo ">> attached; running 3 modes (syscall first)"
./workload --mode syscall --gt "$OUT/tgt.csv" ; sleep 2
./workload --mode uring   --gt "$OUT/tgt.csv" ; sleep 2
./workload --mode sqpoll  --gt "$OUT/tgt.csv" ; sleep 2
sudo pkill -INT -f "monitor syscall_mon.bpf.o"; wait 2>/dev/null
echo ">> events captured:"; echo $(( $(wc -l < "$OUT"/t.csv) - 1 ))
