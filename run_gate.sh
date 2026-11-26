#!/usr/bin/env bash
# run_gate.sh — the DEFENSE experiment: the io_uring_setup gate.
#
# Part A (compatibility + visibility): four conditions, each with the syscall
# monitor attached so we can see what the syscall layer catches. The workload
# always ASKS for io_uring; what happens depends on the gate:
#   no_gate           : io_uring works -> op evades the syscall monitor (the gap)
#   enforce_blocked   : gate denies setup, no --fallback -> op blocked (nothing runs)
#   enforce_fallback  : gate denies setup, --fallback    -> op retried as a syscall,
#                       so the syscall monitor SEES it again (the gate's payoff)
#   enforce_allowed   : workload is allowlisted -> io_uring works (trusted app
#                       unaffected -> shows the policy doesn't break what it permits)
# score_gate.py then reports via_ring / fallback / blocked / evaded per condition.
#
# Part B (cost): setup_bench times raw io_uring_setup() under three gate states
# (none / allowlisted fast path / denied path). The gate runs once per ring, not
# per I/O, so this isolates its true per-ring cost.
#
# NOTE: while the gate is loaded in --enforce mode it gates io_uring_setup
# SYSTEM-WIDE, so non-allowlisted processes anywhere are denied for those few
# seconds. Runs are short and the gate is torn down after each.
set -u
cd "$(dirname "$0")"
sudo -v
# keep sudo fresh; we only ever use targeted waits, never a bare `wait`
( while true; do sudo -n true 2>/dev/null; sleep 50; kill -0 "$$" 2>/dev/null || exit; done ) &
KEEP=$!
trap 'kill "$KEEP" 2>/dev/null; sudo pkill -9 -f "monitor syscall_mon" 2>/dev/null; sudo pkill -9 -f "[.]/gate " 2>/dev/null' EXIT

OUT=/tmp/iouring-study; G="$OUT/gate"; mkdir -p "$G"
DECOY=/var/tmp/iouring-study/targets
SELF="$(pwd)/workload"           # the binary we allowlist in the "allowed" cases

[ -f "$DECOY/shadow.decoy" ] || { echo "decoys missing — creating"; ./setup_decoys.sh >/dev/null; }
for b in workload monitor gate setup_bench syscall_mon.bpf.o gate.bpf.o; do
  [ -e "$b" ] || { echo "missing $b — run 'make' first"; exit 1; }
done

# ---- one compatibility/visibility condition -------------------------------
# args: label  enforce(0/1)  allow_self(0/1)  wl_fallback(0/1)
run_cond () {
  local label=$1 enforce=$2 allow_self=$3 fb=$4
  local GT="$G/${label}_gt.csv" MON="$G/${label}_mon.csv" GEV="$G/${label}_gate.csv"
  sudo rm -f "$GT" "$MON" "$MON.ready" "$GEV"

  # syscall monitor: measures what the syscall layer catches (incl. any fallback)
  sudo timeout 60 ./monitor syscall_mon.bpf.o syscall "$MON" 2>/dev/null &
  local mjob=$!
  local i; for i in $(seq 1 80); do [ -f "$MON.ready" ] && break; sleep 0.25; done

  # gate: load only when this condition uses enforce mode
  local gjob=""
  if [ "$enforce" = 1 ]; then
    local allowarg=""; [ "$allow_self" = 1 ] && allowarg="--allow $SELF"
    sudo ./gate --enforce $allowarg --csv "$GEV" 2>"$G/${label}_gate.log" &
    gjob=$!
    sleep 1.5                     # gate has no ready-file; give it time to attach
  fi

  # the workload always requests io_uring; --fallback decides blocked vs retried
  local fbflag=""; [ "$fb" = 1 ] && fbflag="--fallback"
  ./workload --mode uring $fbflag --gt "$GT" --targets "$DECOY" 2>"$G/${label}_wl.log"
  sleep 1

  sudo pkill -INT -f "monitor syscall_mon.bpf.o"
  [ -n "$gjob" ] && sudo pkill -INT -f "[.]/gate "
  wait "$mjob" 2>/dev/null
  [ -n "$gjob" ] && wait "$gjob" 2>/dev/null

  local wl; wl=$(tail -1 "$G/${label}_wl.log" 2>/dev/null)
  echo "   [$label] $wl"
}

echo "################ PART A — gate compatibility & visibility ################"
run_cond no_gate          0 0 0
run_cond enforce_blocked  1 0 0
run_cond enforce_fallback 1 0 1
run_cond enforce_allowed  1 1 0

echo
echo ">> scoring (score_gate.py)"
python3 score_gate.py \
  --run no_gate          "$G/no_gate_gt.csv"          "$G/no_gate_mon.csv" \
  --run enforce_blocked  "$G/enforce_blocked_gt.csv"  "$G/enforce_blocked_mon.csv" \
  --run enforce_fallback "$G/enforce_fallback_gt.csv" "$G/enforce_fallback_mon.csv" \
  --run enforce_allowed  "$G/enforce_allowed_gt.csv"  "$G/enforce_allowed_mon.csv" \
  --outdir "$G/score"

echo
echo "################ PART B — gate cost on io_uring_setup() ################"
ITERS=${SETUP_ITERS:-100000}
echo "n_per_call is nanoseconds per io_uring_setup()+close, ${ITERS} iters:"

echo "--- baseline: no gate loaded ---"
./setup_bench "$ITERS" | tail -1 | awk -F, '{printf "   no_gate        : %8.1f ns/call   (ok=%s failed=%s)\n",$6,$2,$3}'

echo "--- gate enforce, setup_bench ALLOWLISTED (allowed fast path) ---"
sudo ./gate --enforce --allow "$(pwd)/setup_bench" --csv "$G/cost_allowed_gate.csv" 2>"$G/cost_allowed.log" &
gj=$!; sleep 1.5
./setup_bench "$ITERS" | tail -1 | awk -F, '{printf "   gate_allowed   : %8.1f ns/call   (ok=%s failed=%s)\n",$6,$2,$3}'
sudo pkill -INT -f "[.]/gate "; wait "$gj" 2>/dev/null

echo "--- gate enforce, setup_bench NOT allowlisted (deny path) ---"
sudo ./gate --enforce --csv "$G/cost_denied_gate.csv" 2>"$G/cost_denied.log" &
gj=$!; sleep 1.5
./setup_bench "$ITERS" | tail -1 | awk -F, '{printf "   gate_denied    : %8.1f ns/call   (ok=%s failed=%s)\n",$6,$2,$3}'
sudo pkill -INT -f "[.]/gate "; wait "$gj" 2>/dev/null

echo
echo "gate decision logs + score in: $G/"
