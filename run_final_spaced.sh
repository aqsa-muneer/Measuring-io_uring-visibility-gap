#!/usr/bin/env bash
set -u; cd "$(dirname "$0")"
sudo -v
OUT=/tmp/iouring-study; R="$OUT/final"; mkdir -p "$R"
MODES="syscall uring sqpoll"

run_pass () {
  local TAG=$1; shift
  local EXTRA=$1; shift
  local pairs=("$@") monargs=() GT="$R/${TAG}_gt.csv"
  sudo rm -f "$GT"
  for p in "${pairs[@]}"; do
    local obj=${p%%:*} lbl=${p##*:}
    local csv="$R/${TAG}_${lbl}.csv"
    sudo rm -f "$csv" "$csv.ready"
    sudo timeout 120 ./monitor "$obj" "$lbl" "$csv" &
  done
  for p in "${pairs[@]}"; do
    local lbl=${p##*:}
    local csv="$R/${TAG}_${lbl}.csv"
    for i in $(seq 1 80); do [ -f "$csv.ready" ] && break; sleep 0.25; done
    [ -f "$csv.ready" ] && echo "   attached: $lbl" || echo "   !! NOT attached: $lbl"
  done
  echo ">> [$TAG] running workload (modes: $MODES; extra: '${EXTRA:-none}')"
  for m in $MODES; do ./workload --mode "$m" --gt "$GT" $EXTRA; sleep 1; done
  sleep 2
  for p in "${pairs[@]}"; do local obj=${p%%:*}; sudo pkill -INT -f "monitor $obj"; done
  wait 2>/dev/null
  for p in "${pairs[@]}"; do
    local lbl=${p##*:}
    local csv="$R/${TAG}_${lbl}.csv"
    echo "   $lbl captured $(( $(wc -l < "$csv") - 1 )) events"
    monargs+=(--mon "$csv")
  done
  echo ">> [$TAG] scoring"
  python3 score.py --gt "$GT" "${monargs[@]}" --baseline syscall --outdir "$R/out_$TAG"
}

echo "################ PASS 1 — PRIMARY (buffered): syscall baseline + LSM + io_uring tracepoint ################"
run_pass primary "" syscall_mon.bpf.o:syscall lsm_mon.bpf.o:lsm uring_tp_mon.bpf.o:uring_tp

echo
echo "################ PASS 2 — BLOCK (O_DIRECT): syscall baseline + block-layer ################"
run_pass block "--direct" syscall_mon.bpf.o:syscall block_mon.bpf.o:block
