#!/usr/bin/env bash
set -u; cd "$(dirname "$0")"
OUT=/tmp/iouring-study; ISO="$OUT/iso"; mkdir -p "$ISO"
WL="${1:-}"
sudo -v

# monitor attached across all three modes (lsm, uring_tp, block)
run_all3 () {
  local OBJ=$1 LBL=$2
  local GT="$ISO/${LBL}_gt.csv" CSV="$ISO/${LBL}_mon.csv"
  sudo rm -f "$CSV" "$CSV.ready"; rm -f "$GT"
  sudo timeout 60 ./monitor "$OBJ" "$LBL" "$CSV" &
  for i in $(seq 1 60); do [ -f "$CSV.ready" ] && break; sleep 0.25; done
  echo ">> [$LBL] attached; 3 modes"
  ./workload --mode syscall --gt "$GT" $WL ; sleep 2
  ./workload --mode uring   --gt "$GT" $WL ; sleep 2
  ./workload --mode sqpoll  --gt "$GT" $WL ; sleep 2
  sudo pkill -INT -f "monitor $OBJ"; wait 2>/dev/null
}

# syscall monitor: attached ONLY during syscall mode; io_uring modes fill the
# ground truth afterward with the monitor detached (it is blind to io_uring
# anyway, so its uring/sqpoll recall is 0 by construction).
run_syscall () {
  local OBJ=syscall_mon.bpf.o LBL=syscall
  local GT="$ISO/${LBL}_gt.csv" CSV="$ISO/${LBL}_mon.csv"
  sudo rm -f "$CSV" "$CSV.ready"; rm -f "$GT"
  sudo timeout 30 ./monitor "$OBJ" "$LBL" "$CSV" &
  for i in $(seq 1 60); do [ -f "$CSV.ready" ] && break; sleep 0.25; done
  echo ">> [syscall] attached; syscall mode only"
  ./workload --mode syscall --gt "$GT" $WL ; sleep 2
  sudo pkill -INT -f "monitor $OBJ"; wait 2>/dev/null
  echo ">> [syscall] detached; filling ground truth with io_uring modes"
  ./workload --mode uring  --gt "$GT" $WL
  ./workload --mode sqpoll --gt "$GT" $WL
}

run_syscall
run_all3 lsm_mon.bpf.o      lsm
run_all3 uring_tp_mon.bpf.o uring_tp
run_all3 block_mon.bpf.o    block
echo; echo "================ per-monitor results ================"
for LBL in syscall lsm uring_tp block; do
  echo "----- $LBL -----"
  python3 score.py --gt "$ISO/${LBL}_gt.csv" --mon "$ISO/${LBL}_mon.csv" \
      --outdir "$ISO/out_$LBL" 2>&1 | sed -n '/Recall/,/wrote/p'
done
