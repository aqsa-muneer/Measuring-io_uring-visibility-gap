#!/usr/bin/env bash
# run_cost.sh — the COST half of the study.
#
# For each access mode (syscall / uring / sqpoll) and each monitoring condition
# (no monitor, then each monitor attached), it runs bench.c hammering a decoy
# file and records throughput, latency percentiles, the monitor process's CPU,
# and dropped ring-buffer events. Two scenarios:
#   PRIMARY  — buffered I/O, open-heavy  : none, syscall, lsm, uring_tp
#   BLOCK    — O_DIRECT, disk I/O        : none, block
# Writes one raw CSV; cost_report.py turns it into overhead tables.
set -u
cd "$(dirname "$0")"

BUF_ITERS=${BUF_ITERS:-100000}     # iterations per buffered run
DIR_ITERS=${DIR_ITERS:-20000}      # fewer for O_DIRECT (each op hits the disk)
REPS=${REPS:-3}
DECOY=/var/tmp/iouring-study/targets/shadow.decoy
OUT=/tmp/iouring-study; mkdir -p "$OUT"
RAW="$OUT/cost_raw.csv"
MON_CSV="$OUT/cost_mon.csv"        # throwaway: the monitor's event sink
ERR="$OUT/cost_mon.err"

sudo -v
# keep the sudo credential fresh for the whole run so no later sudo call blocks
# on a password prompt (the default cache expires in ~15 min; this run is longer)
( while true; do sudo -n true 2>/dev/null; sleep 50; kill -0 "$$" 2>/dev/null || exit; done ) &
SUDO_KEEP=$!
trap 'kill "$SUDO_KEEP" 2>/dev/null; sudo pkill -9 -f "/monitor" 2>/dev/null' EXIT

[ -f "$DECOY" ] || { echo "decoys missing — creating"; ./setup_decoys.sh >/dev/null; }
[ -x ./bench ] || { echo "building bench"; gcc -O2 -Wall -o bench bench.c -luring; }

echo "scenario,condition,rep,mode,op,direct,iters,wall_s,throughput,lat_mean_us,p50_us,p99_us,p999_us,workload_cpu_s,monitor_cpu_s,drops" > "$RAW"

# sum of utime+stime (clock ticks) for a pid, robust to spaces in comm
read_cpu () {
  local s r a
  s=$(cat "/proc/$1/stat" 2>/dev/null) || { echo 0; return; }
  r=${s#*) }; a=($r)                 # fields after comm: state is a[0] == field 3
  echo $(( ${a[11]:-0} + ${a[12]:-0} ))   # field14 utime, field15 stime
}

# find the REAL ./monitor process (comm == "monitor") whose cmdline names $1,
# skipping the sudo/timeout wrappers that also contain the object name
find_mon_pid () {
  local pid
  for pid in $(pgrep -x monitor 2>/dev/null); do
    if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q -- "$1"; then
      echo "$pid"; return
    fi
  done
}

# pin the benchmark and the monitor to separate cores to cut scheduling noise.
# sqpoll needs TWO cores (the app thread + io_uring's SQ poller thread); pinning
# it to one core starves the poller and collapses throughput, so give it 2,4.
PIN_WL=""; PIN_WL_SQ=""; PIN_MON=""
if command -v taskset >/dev/null && [ "$(nproc)" -ge 5 ]; then
  PIN_WL="taskset -c 2"; PIN_WL_SQ="taskset -c 2,4"; PIN_MON="taskset -c 3"
  echo "pinning: bench->core2 (sqpoll->cores 2,4), monitor->core3"
fi
# pick the workload pin for a given mode
wl_pin () { if [ "$1" = sqpoll ]; then echo "$PIN_WL_SQ"; else echo "$PIN_WL"; fi; }

# run bench with NO monitor
bench_none () {
  local scen=$1 mode=$2 rep=$3 extra=$4 iters=$5
  local line pin; pin=$(wl_pin "$mode")
  line=$($pin ./bench --mode "$mode" --op read $extra --iters "$iters" --target "$DECOY" 2>/dev/null)
  echo "$scen,none,$rep,$line,0,0" >> "$RAW"
  echo "   [$scen/$mode] none rep$rep: $line"
}

# run bench WITH a monitor attached; measure its CPU + drops
bench_mon () {
  local scen=$1 mode=$2 rep=$3 extra=$4 iters=$5 obj=$6 cond=$7
  sudo rm -f "$MON_CSV" "$MON_CSV.ready"
  sudo $PIN_MON timeout 120 ./monitor "$obj" "$cond" "$MON_CSV" 2>"$ERR" &
  local monjob=$!                    # wait only on THIS job, never the keep-alive loop
  local i; for i in $(seq 1 80); do [ -f "$MON_CSV.ready" ] && break; sleep 0.25; done
  local mpid; mpid=$(find_mon_pid "$obj")
  if [ -z "$mpid" ]; then echo "   !! $cond failed to attach"; sudo pkill -f "monitor $obj"; wait "$monjob" 2>/dev/null; return; fi
  local c0 c1; c0=$(read_cpu "$mpid")
  local line pin; pin=$(wl_pin "$mode")
  line=$($pin ./bench --mode "$mode" --op read $extra --iters "$iters" --target "$DECOY" 2>/dev/null)
  c1=$(read_cpu "$mpid")
  sudo pkill -INT -f "monitor $obj"; wait "$monjob" 2>/dev/null
  local mcpu; mcpu=$(awk "BEGIN{printf \"%.3f\", ($c1-$c0)/100}")
  local drops; drops=$(grep -oE 'dropped \(ringbuf full\): [0-9]+' "$ERR" | grep -oE '[0-9]+$' | tail -1)
  drops=${drops:-0}
  echo "$scen,$cond,$rep,$line,$mcpu,$drops" >> "$RAW"
  echo "   [$scen/$mode] $cond rep$rep: $line  moncpu=${mcpu}s drops=$drops"
}

echo "############ COST PASS: PRIMARY (buffered) ############"
for mode in syscall uring sqpoll; do
  for rep in $(seq 1 "$REPS"); do
    bench_none primary "$mode" "$rep" ""  "$BUF_ITERS"
    bench_mon  primary "$mode" "$rep" ""  "$BUF_ITERS" syscall_mon.bpf.o  syscall
    bench_mon  primary "$mode" "$rep" ""  "$BUF_ITERS" lsm_mon.bpf.o      lsm
    bench_mon  primary "$mode" "$rep" ""  "$BUF_ITERS" uring_tp_mon.bpf.o uring_tp
  done
done

echo "############ COST PASS: BLOCK (O_DIRECT) ############"
for mode in syscall uring sqpoll; do
  for rep in $(seq 1 "$REPS"); do
    bench_none block "$mode" "$rep" "--direct" "$DIR_ITERS"
    bench_mon  block "$mode" "$rep" "--direct" "$DIR_ITERS" block_mon.bpf.o block
  done
done

echo
echo "############ RESULTS ############"
python3 cost_report.py --csv "$RAW"
echo
echo "raw per-run data: $RAW"
