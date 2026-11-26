# Compares runs (e.g. no gate / gate on / gate with the workload allowlisted)
# on the question the gate is meant to answer: "Of the sensitive file operations an attacker ATTEMPTED, how many were
#      carried out without the syscall monitor seeing them?"

import argparse
import csv
import os
import sys
from bisect import bisect_left
from collections import defaultdict


def read_gt(path):
    rows = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            r["ts_submit_ns"] = int(r["ts_submit_ns"])
            r["tgid"] = int(r["tgid"])
            r.setdefault("path_used", r["mode"])        # old-format files
            r.setdefault("setup_errno", "0")
            if not r["path_used"]:
                r["path_used"] = r["mode"]
            rows.append(r)
    return rows


def read_mon(path):
    ev = defaultdict(list)          # (op, path) -> [(ts, tgid)]
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            ev[(r["op"], r["path"])].append((int(r["ts_ns"]), int(r["tgid"])))
    for k in ev:
        ev[k].sort()
    return ev


def match(gt, mon, fwd_ns, back_ns):
    """Mark each gt row detected / attributed. Same rule as score.py."""
    by_key = defaultdict(list)
    for i, r in enumerate(gt):
        by_key[(r["op"], r["path"])].append(i)

    detected = [False] * len(gt)
    attributed = [False] * len(gt)
    for key, idxs in by_key.items():
        events = mon.get(key)
        if not events:
            continue
        ts = [e[0] for e in events]
        used = [False] * len(events)
        for i in sorted(idxs, key=lambda j: gt[j]["ts_submit_ns"]):
            t = gt[i]["ts_submit_ns"]
            lo, hi = t - back_ns, t + fwd_ns
            best, best_d = None, None
            k = bisect_left(ts, lo)
            while k < len(ts) and ts[k] <= hi:
                if not used[k]:
                    d = abs(ts[k] - t)
                    if best is None or d < best_d:
                        best, best_d = k, d
                k += 1
            if best is None:
                continue
            used[best] = True
            detected[i] = True
            attributed[i] = events[best][1] == gt[i]["tgid"]
    return detected, attributed


def main():
    ap = argparse.ArgumentParser(description="score the io_uring_setup gate experiment")
    ap.add_argument("--run", nargs=3, action="append", required=True,
                    metavar=("LABEL", "GT_CSV", "MON_CSV"))
    ap.add_argument("--window-ms", type=float, default=50.0)
    ap.add_argument("--back-ms", type=float, default=2.0)
    ap.add_argument("--outdir", default="out")
    a = ap.parse_args()

    fwd, back = int(a.window_ms * 1e6), int(a.back_ms * 1e6)
    out_rows = []
    for label, gt_path, mon_path in a.run:
        gt = read_gt(gt_path)
        mon = read_mon(mon_path)
        det, att = match(gt, mon, fwd, back)

        by_mode = defaultdict(list)
        for i, r in enumerate(gt):
            by_mode[r["mode"]].append(i)

        for mode in ("syscall", "uring", "sqpoll"):
            idxs = by_mode.get(mode, [])
            n = len(idxs)
            if n == 0:
                continue
            used = [gt[i]["path_used"] for i in idxs]
            via_ring = sum(u in ("uring", "sqpoll") for u in used)
            blocked = sum(u == "none" for u in used)
            fallback = sum(u == "syscall" for u in used) if mode != "syscall" else 0
            d = sum(det[i] for i in idxs)
            at = sum(att[i] for i in idxs)
            evaded = sum(1 for i in idxs
                         if gt[i]["path_used"] != "none" and not det[i])
            setup_err = sorted({gt[i]["setup_errno"] for i in idxs} - {"0"})
            out_rows.append(dict(
                run=label, mode=mode, attempted=n, via_ring=via_ring,
                fallback=fallback, blocked=blocked,
                recall=round(d / n, 2), attributed=round(at / n, 2),
                evaded=round(evaded / n, 2),
                setup_errno=";".join(setup_err) or "0"))

    os.makedirs(a.outdir, exist_ok=True)
    out_csv = os.path.join(a.outdir, "gate_summary.csv")
    fields = ["run", "mode", "attempted", "via_ring", "fallback", "blocked",
              "recall", "attributed", "evaded", "setup_errno"]
    with open(out_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(out_rows)

    # console table
    widths = {f: max(len(f), *(len(str(r[f])) for r in out_rows)) for f in fields}
    print("  ".join(f.ljust(widths[f]) for f in fields))
    for r in out_rows:
        print("  ".join(str(r[f]).ljust(widths[f]) for f in fields))
    print(f"\nwrote {out_csv}")


if __name__ == "__main__":
    sys.exit(main())