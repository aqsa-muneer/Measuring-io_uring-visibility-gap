set -euo pipefail
cd "$(dirname "$0")"

OUT=/tmp/iouring-study/gate
N_BENCH=${N_BENCH:-100000}
mkdir -p "$OUT"
rm -f "$OUT"/*.csv "$OUT"/*.log

[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
for f in monitor syscall_mon.bpf.o gate gate.bpf.o workload setup_bench; do
    [[ -e $f ]] || { echo "missing ./$f — build first (make; make -f Makefile.gate)"; exit 1; }
done
[[ -f setup_decoys.sh ]] && bash setup_decoys.sh >/dev/null

HAVE_LSM=0; [[ -f lsm_mon.bpf.o ]] && HAVE_LSM=1

# --- helpers -----------------------------------------------------------------
# Monitors and the gate install their own SIGINT/SIGTERM handlers, so the
# signals below reach them even though background jobs in a script ignore
# SIGINT by default.
start_mons() {   # $1 = run label
    ./monitor syscall_mon.bpf.o syscall "$OUT/sys_$1.csv" >"$OUT/sysmon_$1.log" 2>&1 &
    SYS_PID=$!
    if (( HAVE_LSM )); then
        ./monitor lsm_mon.bpf.o lsm "$OUT/lsm_$1.csv" >"$OUT/lsmmon_$1.log" 2>&1 &
        LSM_PID=$!
    fi
    sleep 2
}
stop_mons() {
    kill -INT "$SYS_PID"; wait "$SYS_PID" || true
    if (( HAVE_LSM )); then kill -INT "$LSM_PID"; wait "$LSM_PID" || true; fi
}
start_gate() {   # args passed to ./gate; first arg = run label
    local label=$1; shift
    ./gate "$@" --csv "$OUT/gate_$label.csv" >"$OUT/gate_$label.log" 2>&1 &
    GATE_PID=$!
    sleep 2
    kill -0 "$GATE_PID" 2>/dev/null || { echo "gate failed to start:"; cat "$OUT/gate_$label.log"; exit 1; }
}
stop_gate() { kill -TERM "$GATE_PID"; wait "$GATE_PID" || true; }

run_workload() { # $1 = run label. Runs are spaced 1 s apart so the scorer's
                 # time-window matching can't cross-match between them.
    for m in uring sqpoll; do
        ./workload --mode "$m" --fallback --gt "$OUT/gt_$1.csv"
        sleep 1
    done
}

# --- 1. no gate ---------------------------------------------------------------
echo ">> run: nogate"
start_mons nogate
run_workload nogate
stop_mons

# --- 2. gate on, workload not allowlisted ------------------------------------
echo ">> run: gate (enforce, empty allowlist)"
start_gate gate --enforce
start_mons gate
run_workload gate
stop_mons
stop_gate

# --- 3. gate on, workload allowlisted (the bypass) ----------------------------
echo ">> run: allowed (enforce, ./workload allowlisted)"
start_gate allowed --enforce --allow ./workload
start_mons allowed
run_workload allowed
stop_mons
stop_gate

# --- 4. cost of the gate on io_uring_setup ------------------------------------
# setup latency is noisy (~10 us per call, scheduler/cache effects), so each
# condition is run REPEATS times, interleaved, and you report the median.
REPEATS=${REPEATS:-5}
echo ">> cost: io_uring_setup x $N_BENCH, $REPEATS repeats"
COST="$OUT/setup_cost.csv"
echo "condition,rep,n,ok,failed,first_errno,total_ns,ns_per_call" > "$COST"
bench() { ./setup_bench "$N_BENCH" | tail -1 | sed "s/^/$1,$2,/" >> "$COST"; }

for rep in $(seq 1 "$REPEATS"); do
    bench no_gate "$rep"
    start_gate bench_allowed --enforce --allow ./setup_bench
    bench gate_allowed "$rep"   # allowed fast path: one hash-map lookup
    stop_gate
    start_gate bench_denied --enforce
    bench gate_denied "$rep"    # deny path: lookup + ringbuf event + -EPERM
    stop_gate
done

# --- score -----------------------------------------------------------------------
echo
echo "== syscall monitor =="
python3 score_gate.py \
    --run nogate  "$OUT/gt_nogate.csv"  "$OUT/sys_nogate.csv" \
    --run gate    "$OUT/gt_gate.csv"    "$OUT/sys_gate.csv" \
    --run allowed "$OUT/gt_allowed.csv" "$OUT/sys_allowed.csv" \
    --outdir "$OUT/out_syscall"
if (( HAVE_LSM )); then
    echo
    echo "== lsm monitor (should stay ~1.00 recall in every run) =="
    python3 score_gate.py \
        --run nogate  "$OUT/gt_nogate.csv"  "$OUT/lsm_nogate.csv" \
        --run gate    "$OUT/gt_gate.csv"    "$OUT/lsm_gate.csv" \
        --run allowed "$OUT/gt_allowed.csv" "$OUT/lsm_allowed.csv" \
        --outdir "$OUT/out_lsm"
fi
echo
echo "== io_uring_setup cost (median ns per call) =="
python3 - "$COST" <<'PY2'
import csv, sys, statistics
rows = list(csv.DictReader(open(sys.argv[1])))
for cond in ("no_gate", "gate_allowed", "gate_denied"):
    v = [float(r["ns_per_call"]) for r in rows if r["condition"] == cond]
    print(f"  {cond:13s} median {statistics.median(v):9.1f} ns   (min {min(v):.1f}, max {max(v):.1f}, n={len(v)})")
PY2
echo
echo "gate decisions in the gate run (comm, verdict, exe):"
tail -n +2 "$OUT/gate_gate.csv" | cut -d, -f4,5,8 | sort | uniq -c || true