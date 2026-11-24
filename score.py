import argparse
import os
import sys
import numpy as np
import pandas as pd

GT_COLS  = ["op_id","ts_submit_ns","mode","op","path","tgid","tid","result_errno"]
MON_COLS = ["ts_ns","source","tgid","tid","comm","op","path"]

def load_ground_truth(path, basename_match):
    gt = pd.read_csv(path)
    missing = [c for c in GT_COLS if c not in gt.columns]
    if missing:
        sys.exit(f"ground truth missing columns: {missing}")
    gt = gt.reset_index(drop=True)
    gt["gt_uid"] = gt.index                 # unique key per attempted op
    gt["mpath"] = gt["path"].map(os.path.basename) if basename_match else gt["path"]
    return gt

def load_monitor(path, basename_match):
    mon = pd.read_csv(path)
    for c in MON_COLS:
        if c not in mon.columns:
            sys.exit(f"{path} missing column: {c}")
    if mon.empty:
        return mon
    mon["mpath"] = mon["path"].map(os.path.basename) if basename_match else mon["path"]
    return mon

def match_monitor(gt, mon, back_ns, fwd_ns):
    """Return four boolean Series aligned to gt.index, four bars of strictness:

      attributed  : op + path + PID all correct   (the recovery bar)
      detected    : op + path correct             (recall / "could name the file")
      activity    : op + PID correct, path ignored (path-free: did it get the PID?)
      op_activity : op correct, path & PID ignored (loosest: saw an op of that type)

    The strong bars (detected/attributed) use greedy nearest-time matching
    within each (op, path) group, each monitor event used once. The path-free
    bars are existence checks by op — they exist to fairly characterize the
    io_uring-tracepoint and block monitors, which emit NO path: those score ~0
    on recall but can still show whether they recovered the PID and the op type.
    """
    detected    = pd.Series(False, index=gt.index)
    attributed  = pd.Series(False, index=gt.index)
    activity    = pd.Series(False, index=gt.index)   # op + pid, path ignored
    op_activity = pd.Series(False, index=gt.index)   # op only
    if mon is None or mon.empty:
        return detected, attributed, activity, op_activity

    # ---- strong + path bars: unique nearest within (op, path) ----
    mon_groups = {k: g for k, g in mon.groupby(["op", "mpath"])}
    for (op, mpath), gg in gt.groupby(["op", "mpath"]):
        mg = mon_groups.get((op, mpath))
        if mg is None:
            continue
        mon_ts   = mg["ts_ns"].to_numpy()
        mon_tgid = mg["tgid"].to_numpy()
        order    = np.argsort(mon_ts)
        mon_ts, mon_tgid = mon_ts[order], mon_tgid[order]
        used = np.zeros(len(mon_ts), dtype=bool)
        for uid, t, gtgid in gg.sort_values("ts_submit_ns")[
                ["gt_uid", "ts_submit_ns", "tgid"]].itertuples(index=False):
            cand = np.where((~used) & (mon_ts >= t - back_ns) & (mon_ts <= t + fwd_ns))[0]
            if cand.size == 0:
                continue
            k = cand[np.argmin(np.abs(mon_ts[cand] - t))]
            used[k] = True
            detected[uid]   = True
            attributed[uid] = bool(mon_tgid[k] == gtgid)

    # ---- path-free bars: existence by op (not unique; diagnostic) ----
    op_arrays = {}
    for op, g in mon.groupby("op"):
        ts = g["ts_ns"].to_numpy(); tg = g["tgid"].to_numpy()
        o = np.argsort(ts)
        op_arrays[op] = (ts[o], tg[o])
    for uid, op, t, gtgid in gt[["gt_uid", "op", "ts_submit_ns", "tgid"]].itertuples(index=False):
        arr = op_arrays.get(op)
        if arr is None:
            continue
        ts, tg = arr
        lo = np.searchsorted(ts, t - back_ns, "left")
        hi = np.searchsorted(ts, t + fwd_ns, "right")
        if hi > lo:
            op_activity[uid] = True
            if np.any(tg[lo:hi] == gtgid):
                activity[uid] = True

    return detected, attributed, activity, op_activity

def main():
    ap = argparse.ArgumentParser(description="score io_uring visibility monitors")
    ap.add_argument("--gt", required=True, help="ground_truth.csv")
    ap.add_argument("--mon", action="append", default=[],
                    help="a monitor CSV; repeat for each (source is read from the file)")
    ap.add_argument("--baseline", default="syscall",
                    help="source label whose misses define 'lost visibility' (default: syscall)")
    ap.add_argument("--window-ms", type=float, default=50.0,
                    help="forward match window in ms (default 50)")
    ap.add_argument("--back-ms", type=float, default=2.0,
                    help="backward tolerance in ms for clock jitter (default 2)")
    ap.add_argument("--basename", action="store_true",
                    help="match on file basename instead of full path")
    ap.add_argument("--outdir", default=".", help="where to write the CSV outputs")
    args = ap.parse_args()

    back_ns = int(args.back_ms * 1e6)
    fwd_ns  = int(args.window_ms * 1e6)
    os.makedirs(args.outdir, exist_ok=True)

    gt = load_ground_truth(args.gt, args.basename)

    # per-op detection/attribution table, one column pair per monitor source
    per_op = gt[["gt_uid","mode","op","path","tgid"]].copy()
    sources = []
    for mpath in args.mon:
        mon = load_monitor(mpath, args.basename)
        src = (mon["source"].iloc[0] if not mon.empty
               else os.path.splitext(os.path.basename(mpath))[0])
        sources.append(src)
        det, attr, act, opact = match_monitor(gt, mon, back_ns, fwd_ns)
        per_op[f"{src}_detected"]    = det.values
        per_op[f"{src}_attributed"]  = attr.values
        per_op[f"{src}_activity"]    = act.values
        per_op[f"{src}_op_activity"] = opact.values

    if not sources:
        sys.exit("no monitors given; pass --mon at least once")

    # ---- summary table: recall + attribution, per (source, mode) ----
    rows = []
    for src in sources:
        for mode, g in per_op.groupby("mode"):
            attempted = len(g)
            detected  = int(g[f"{src}_detected"].sum())
            attributed= int(g[f"{src}_attributed"].sum())
            activity  = int(g[f"{src}_activity"].sum())
            op_act    = int(g[f"{src}_op_activity"].sum())
            rows.append(dict(
                source=src, mode=mode,
                attempted=attempted,
                recall=detected/attempted if attempted else np.nan,                 # op+path
                attribution_acc=attributed/detected if detected else np.nan,         # of detected, pid right
                pid_recall=activity/attempted if attempted else np.nan,              # op+pid, path-free
                op_recall=op_act/attempted if attempted else np.nan,                 # op only
            ))
    summary = pd.DataFrame(rows)

    # ---- recovery fraction, per (source, mode) ----
    base_det = f"{args.baseline}_detected"
    rec_rows = []
    if base_det in per_op.columns:
        for src in sources:
            if src == args.baseline:
                continue
            for mode, g in per_op.groupby("mode"):
                lost = ~g[base_det]                      # syscall monitor missed it
                n_lost = int(lost.sum())
                recovered = int((g[f"{src}_attributed"] & lost).sum())
                rec_rows.append(dict(
                    source=src, mode=mode,
                    lost_by_baseline=n_lost,
                    recovered=recovered,
                    recovery_frac=recovered/n_lost if n_lost else np.nan,
                ))
    recovery = pd.DataFrame(rec_rows)

    # ---- write + print ----
    per_op.to_csv(os.path.join(args.outdir, "per_op.csv"), index=False)
    summary.to_csv(os.path.join(args.outdir, "summary.csv"), index=False)
    recovery.to_csv(os.path.join(args.outdir, "recovery.csv"), index=False)

    pd.set_option("display.width", 120)
    pd.set_option("display.max_columns", 20)
    print("\n=== Recall & attribution (per monitor × mode) ===")
    print("recall=op+path  attribution_acc=pid-right|detected  pid_recall=op+pid(no path)  op_recall=op only")
    print(summary.to_string(index=False, formatters={
          "recall": "{:.2f}".format, "attribution_acc": "{:.2f}".format,
          "pid_recall": "{:.2f}".format, "op_recall": "{:.2f}".format}))
    print("\n=== Recovery fraction  (of ops the '%s' monitor lost) ===" % args.baseline)
    if recovery.empty:
        print("(baseline not among monitors, or no other monitors)")
    else:
        print(recovery.to_string(index=False,
              formatters={"recovery_frac": "{:.2f}".format}))
    print("\nwrote per_op.csv, summary.csv, recovery.csv to", args.outdir)

if __name__ == "__main__":
    main()