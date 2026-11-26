# flood_report.py — aggregate the flood-evasion raw CSV.
#
# Raw columns: monitor,threads,rep,flood_rate,written,drops,drop_pct,
#              needles,needle_seen,needle_frac
# Each run fires many needles and records needle_frac = (logged / fired), a
# smooth per-run detection probability. For each (monitor, threads) we report
# the median flood rate, median drop %, and the mean needle detection fraction.
# As flood intensity rises, drop % climbs and needle detection falls toward 0:
# that is the evasion.

import argparse
import pandas as pd

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    a = ap.parse_args()
    df = pd.read_csv(a.csv)
    if df.empty:
        print("no rows in", a.csv); return

    g = (df.groupby(["monitor", "threads"], as_index=False)
           .agg(reps=("rep", "count"),
                flood_rate=("flood_rate", "median"),
                drop_pct=("drop_pct", "median"),
                needle_detect=("needle_frac", "mean")))

    pd.set_option("display.width", 120)
    for mon in ["syscall", "lsm", "uring_tp", "block"]:
        sub = g[g.monitor == mon].sort_values("threads")
        if sub.empty:
            continue
        print(f"\n=== {mon} monitor — needle detection under flood ===")
        print("threads=0 is the control (no flood → detection should be ~1.00)")
        print(sub[["threads", "flood_rate", "drop_pct", "needle_detect", "reps"]]
              .to_string(index=False, formatters={
                  "flood_rate": "{:,.0f}".format,
                  "drop_pct": "{:.1f}".format,
                  "needle_detect": "{:.3f}".format}))

    g.to_csv("flood_summary.csv", index=False)
    print("\nwrote flood_summary.csv")

if __name__ == "__main__":
    main()
