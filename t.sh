#!/usr/bin/env bash
set -u; cd "$(dirname "$0")"
OUT=/tmp/iouring-study
sudo -v
sudo rm -f "$OUT"/t.csv "$OUT"/t.csv.ready
sudo timeout 10 ./monitor syscall_mon.bpf.o syscall "$OUT/t.csv" &
for i in $(seq 1 40); do [ -f "$OUT"/t.csv.ready ] && break; sleep 0.25; done
echo ">> attached; running ONLY syscall-mode workload"
./workload --mode syscall
sleep 2
sudo pkill -INT -f "monitor syscall_mon.bpf.o"; wait 2>/dev/null
echo ">> events captured:"; echo $(( $(wc -l < "$OUT"/t.csv) - 1 ))
