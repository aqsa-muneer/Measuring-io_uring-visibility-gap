#!/usr/bin/env bash
# run_flood.sh — io_uring flood-evasion stress test.
#
# An io_uring-capable attacker overflows a monitor's ring buffer with a flood of
# benign watched-file accesses (through io_uring by default) so that real
# accesses (the "needles") are dropped and go unseen. Sweeps flood intensity
# (thread count) against the syscall and LSM monitors and measures, per
# intensity: the flood's ops/s, the monitor's drop %, and the fraction of
# needles detected.
#
#   * LSM monitor  : sees io_uring opens -> this is the real target. Detection
#                    starts ~1.0 (no flood) and falls as the io_uring flood
#                    saturates its buffer: the attack on the gap-closing defense.
#   * syscall monitor : blind to io_uring entirely -> detection ~0 at EVERY
#                    thread count incl. the control, because io_uring evades it
#                    with or without a flood (the original gap).
#
# FLOODMODE controls the channel: uring (default) | sqpoll | syscall.
set -u
cd "$(dirname "$0")"
sudo -v
( while true; do sudo -n true 2>/dev/null; sleep 50; kill -0 "$$" 2>/dev/null || exit; done ) &
KEEP=$!
trap 'kill "$KEEP" 2>/dev/null; sudo pkill -9 -f "monitor .*_mon.bpf.o" 2>/dev/null; pkill -9 flood 2>/dev/null' EXIT

OUT=/tmp/iouring-study; F="$OUT/flood"; mkdir -p "$F"
DECOY=/var/tmp/iouring-study/targets
[ -f "$DECOY/shadow.decoy" ] || { echo "decoys missing — creating"; ./setup_decoys.sh >/dev/null; }
# the needle: a watched file touched exactly once per run, by nothing but flood's
# main thread, so its presence in the monitor CSV == "the real access was seen"
echo "NEEDLE secret - the attacker's single real read" > "$DECOY/needle.decoy" 2>/dev/null \
  || sudo sh -c "echo NEEDLE > $DECOY/needle.decoy"

RAW="$F/flood_raw.csv"
echo "monitor,threads,rep,flood_rate,written,drops,drop_pct,needles,needle_seen,needle_frac" > "$RAW"

THREADS="${THREADS:-0 1 2 4 8}"     # 0 = control
REPS="${REPS:-5}"
WARM="${WARM:-300}"; HOLD="${HOLD:-1000}"; NEEDLES="${NEEDLES:-200}"
FLOODMODE="${FLOODMODE:-uring}"     # uring | sqpoll | syscall
echo "flood channel: $FLOODMODE"

run_mon () {   # $1 obj  $2 label
  local obj=$1 lbl=$2 th r
  for th in $THREADS; do
    for r in $(seq 1 "$REPS"); do
      local CSV="$F/${lbl}_${th}_${r}.csv" ERR="$F/${lbl}_${th}_${r}.err"
      sudo rm -f "$CSV" "$CSV.ready"
      sudo timeout 40 ./monitor "$obj" "$lbl" "$CSV" 2>"$ERR" &
      local mjob=$! i
      for i in $(seq 1 80); do [ -f "$CSV.ready" ] && break; sleep 0.25; done
      local fo
      fo=$(./flood --mode "$FLOODMODE" --threads "$th" --targets "$DECOY" \
                   --needle "$DECOY/needle.decoy" --needles "$NEEDLES" \
                   --warmup-ms "$WARM" --hold-ms "$HOLD" 2>/dev/null)
      sleep 0.3
      # stop the monitor and WAIT for the real process to exit, so its summary
      # line (events written / dropped) is flushed before we read the log
      sudo pkill -INT -f "monitor $obj"
      for i in $(seq 1 50); do pgrep -f "monitor $obj" >/dev/null 2>&1 || break; sleep 0.1; done
      wait "$mjob" 2>/dev/null
      local rate written drops pct needles seen frac
      rate=$(echo "$fo" | sed -n 's/.*flood_ops_per_s,\([0-9]*\).*/\1/p'); rate=${rate:-0}
      needles=$(echo "$fo" | sed -n 's/.*needles,\([0-9]*\).*/\1/p'); needles=${needles:-$NEEDLES}
      written=$(grep -oE 'events written: [0-9]+' "$ERR" | grep -oE '[0-9]+$' | tail -1); written=${written:-0}
      drops=$(grep -oE 'dropped \(ringbuf full\): [0-9]+' "$ERR" | grep -oE '[0-9]+$' | tail -1); drops=${drops:-0}
      pct=$(awk "BEGIN{t=$written+$drops; printf \"%.1f\", (t>0?100*$drops/t:0)}")
      # detection = fraction of the fired needles the monitor logged
      seen=$(grep -c "needle.decoy" "$CSV" 2>/dev/null); seen=${seen:-0}
      frac=$(awk "BEGIN{printf \"%.3f\", ($needles>0?$seen/$needles:0)}")
      echo "$lbl,$th,$r,$rate,$written,$drops,$pct,$needles,$seen,$frac" >> "$RAW"
      echo "   [$lbl th=$th r=$r] flood=${rate}/s drop=${pct}% needle_seen=$seen/$needles (${frac})"
    done
  done
}

echo "############ FLOOD EVASION: syscall monitor ############"
run_mon syscall_mon.bpf.o syscall
echo "############ FLOOD EVASION: LSM monitor ############"
run_mon lsm_mon.bpf.o lsm

echo
echo "############ RESULTS ############"
python3 flood_report.py --csv "$RAW"
echo
echo "raw per-run data: $RAW"
