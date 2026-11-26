# cost_report.py — aggregate the raw cost CSV into overhead tables.
#
# Input CSV columns (written by run_cost.sh):
#   scenario,condition,rep,mode,op,direct,iters,wall_s,throughput,
#   lat_mean_us,p50_us,p99_us,p999_us,workload_cpu_s,monitor_cpu_s,drops
#
# We take the MEDIAN across reps for each (scenario, mode, condition), then
# express each monitor's cost relative to the 'none' (no-monitor) baseline in
# the same scenario+mode: throughput overhead %, and absolute latency deltas.
# monitor_cpu_s is the CPU the monitor PROCESS burned during the run; drops is
# ring-buffer events lost under load.

import argparse
import pandas as pd
import numpy as np

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    if df.empty:
        print("no rows in", args.csv); return

    keys = ["scenario", "mode", "condition"]
    agg = (df.groupby(keys, as_index=False)
             .agg(throughput=("throughput", "median"),
                  p50_us=("p50_us", "median"),
                  p99_us=("p99_us", "median"),
                  p999_us=("p999_us", "median"),
                  workload_cpu_s=("workload_cpu_s", "median"),
                  monitor_cpu_s=("monitor_cpu_s", "median"),
                  drops=("drops", "median"),
                  reps=("rep", "count")))

    # baseline throughput/latency/CPU per (scenario, mode) is the 'none' condition
    base = (agg[agg["condition"] == "none"]
            .set_index(["scenario", "mode"])[["throughput", "p50_us", "p99_us", "workload_cpu_s"]]
            .rename(columns={"throughput": "base_tput", "p50_us": "base_p50",
                             "p99_us": "base_p99", "workload_cpu_s": "base_wcpu"}))
    agg = agg.join(base, on=["scenario", "mode"])

    agg["tput_overhead_%"] = (1 - agg["throughput"] / agg["base_tput"]) * 100
    agg["p50_delta_us"]    = agg["p50_us"] - agg["base_p50"]
    agg["p99_delta_us"]    = agg["p99_us"] - agg["base_p99"]
    # extra workload CPU vs baseline = the monitor's in-kernel BPF cost per run
    agg["wl_cpu_delta_s"]  = agg["workload_cpu_s"] - agg["base_wcpu"]

    # stable ordering: baseline first, then monitors
    order = {"none": 0, "syscall": 1, "lsm": 2, "uring_tp": 3, "block": 4}
    agg["_o"] = agg["condition"].map(order).fillna(9)

    pd.set_option("display.width", 160)
    pd.set_option("display.max_columns", 30)

    for scen in ["primary", "block"]:
        sdf = agg[agg["scenario"] == scen]
        if sdf.empty:
            continue
        title = ("PRIMARY — buffered I/O (open-heavy hot path)" if scen == "primary"
                 else "BLOCK — O_DIRECT (disk I/O hot path)")
        print(f"\n================= COST: {title} =================")
        for mode in ["syscall", "uring", "sqpoll"]:
            mdf = sdf[sdf["mode"] == mode].sort_values("_o")
            if mdf.empty:
                continue
            print(f"\n--- mode = {mode} ---")
            show = mdf[["condition", "throughput", "tput_overhead_%",
                        "p50_us", "p99_us", "wl_cpu_delta_s",
                        "monitor_cpu_s", "drops"]].copy()
            print(show.to_string(index=False, formatters={
                "throughput":      "{:,.0f}".format,
                "tput_overhead_%": "{:+.1f}".format,
                "p50_us":          "{:.2f}".format,
                "p99_us":          "{:.2f}".format,
                "wl_cpu_delta_s":  "{:+.3f}".format,
                "p50_delta_us":    "{:+.2f}".format,
                "p99_delta_us":    "{:+.2f}".format,
                "monitor_cpu_s":   "{:.3f}".format,
                "drops":           "{:,.0f}".format,
            }))

    agg.drop(columns=["_o"]).to_csv("cost_summary.csv", index=False)
    print("\nwrote cost_summary.csv")

if __name__ == "__main__":
    main()
