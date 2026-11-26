import argparse
import glob
import os
import sys

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")                     # no display needed; we only save PNGs
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

# ---------------------------------------------------------------- labels ----
# The raw names score.py uses, mapped to what a reader of the report should see.
# Order matters: it is the row/bar order in every figure (weakest-to-strongest
# story: the blind baseline first, the defence that recovers everything next).
LAYERS = {                      # source prefix in per_op.csv -> display name
    "syscall":  "Syscall tracepoints",
    "lsm":      "BPF-LSM hooks",
    "uring_tp": "io_uring tracepoints",
    "block":    "Block layer",
}
MODES = {                       # ground-truth 'mode' -> display name
    "syscall": "Plain syscalls",
    "uring":   "io_uring",
    "sqpoll":  "io_uring + SQPOLL",
}
# Match strictness, strictest first. Each key is a normalized metric name
# (see metric_kind) -> display label.
METRICS = {
    "attributed": "op + path + PID",
    "detected":   "op + path (recall)",
    "pid":        "op + PID (no path)",
    "op":         "op only",
}
BASE_COLS = {"gt_uid", "op_id", "mode", "op", "path", "tgid", "tid",
             "ts_submit_ns", "result_errno", "mpath"}

# Colors: categorical slots 1-4 of the validated reference palette, fixed to
# the LAYER (not to its rank), so a layer is the same color in every figure.
LAYER_COLORS = {"syscall": "#257de0", "lsm": "#f47230",
                "uring_tp": "#00b894", "block": "#f2a600"}
# Sequential single-hue blue ramp (light = 0 %, dark = 100 %) for heatmaps.
SEQ = LinearSegmentedColormap.from_list(
    "seq_blue", ["#f4f8fd", "#cce3fd", "#84b9f3", "#338ced", "#1b64be", "#0e3d7e"])
INK, INK2, GRID = "#191919", "#666666", "#e6e6e6"


# ---------------------------------------------------------- loading ---------
def resolve_runs(args):
    """Turn CLI arguments into a list of (label, per_op.csv path)."""
    runs = []
    for a in args:
        label, _, target = a.rpartition("=") if "=" in a else ("", "", a)
        matches = sorted(glob.glob(target)) or [target]   # allow "out*"
        for m in matches:
            csv = os.path.join(m, "per_op.csv") if os.path.isdir(m) else m
            if not os.path.isfile(csv):
                print(f"skip: no per_op.csv at {m}", file=sys.stderr)
                continue
            name = label if (label and len(matches) == 1) else \
                os.path.basename(os.path.dirname(os.path.abspath(csv)))
            runs.append((name, csv))
    if not runs:
        sys.exit("no per_op.csv found — pass the folders score.py wrote with --outdir")
    # two folders with the same basename would collide: number them
    seen = {}
    out = []
    for name, csv in runs:
        seen[name] = seen.get(name, 0) + 1
        out.append((name if seen[name] == 1 else f"{name}#{seen[name]}", csv))
    return out


def split_column(col):
    """'uring_tp_detected' -> ('uring_tp', 'detected').

    Source names can contain underscores (uring_tp, syscall_mon), so match the
    longest known layer prefix first; '_mon' is dropped because score.py falls
    back to the CSV file stem (syscall_mon) when a monitor wrote no events.
    """
    c = col.replace("_mon_", "_")
    for layer in sorted(LAYERS, key=len, reverse=True):
        if c.startswith(layer + "_"):
            return layer, c[len(layer) + 1:]
    layer, _, rest = c.partition("_")          # unknown layer: best effort
    return layer, rest


def metric_kind(raw):
    """Normalize the scorer's metric column suffix to a METRICS key."""
    r = raw.lower()
    if r == "detected":
        return "detected"
    if r == "attributed":
        return "attributed"
    if r.startswith("op") and ("activity" in r or "recall" in r):
        return "op"                             # op_activity / op_recall
    if "activity" in r or "pid" in r:
        return "pid"                            # activity / pid_activity
    return None


def to_bool(s):
    if s.dtype == bool:
        return s
    return s.astype(str).str.strip().str.lower().isin({"true", "1", "yes"})


def load_long(runs):
    """Stack every run's per_op.csv into one long table:
    run, layer, mode, op, metric, hit (0/1), one row per attempted op."""
    frames = []
    for run, csv in runs:
        df = pd.read_csv(csv)
        for need in ("mode", "op"):
            if need not in df.columns:
                sys.exit(f"{csv}: missing column '{need}' — is this score.py's per_op.csv?")
        for col in df.columns:
            if col in BASE_COLS:
                continue
            layer, raw = split_column(col)
            kind = metric_kind(raw)
            if kind is None:
                continue
            frames.append(pd.DataFrame({
                "run": run, "layer": layer, "mode": df["mode"].astype(str),
                "op": df["op"].astype(str), "metric": kind,
                "hit": to_bool(df[col]).astype(int)}))
    if not frames:
        sys.exit("no <layer>_<metric> columns found in any per_op.csv")
    return pd.concat(frames, ignore_index=True)


def ordered(values, preferred):
    """Known names in the preferred order, then any unknown ones alphabetically."""
    vals = list(dict.fromkeys(values))
    return [v for v in preferred if v in vals] + sorted(v for v in vals if v not in preferred)


# ---------------------------------------------------------- figures ---------
def style_axes(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=9, length=0)


def heatmap_grid(long, layers, modes, ops, metrics, n_runs, path):
    """Rows = metric, columns = path; each panel = layer x operation."""
    agg = (long.groupby(["metric", "mode", "layer", "op"])["hit"]
               .agg(["sum", "count"]).reset_index())
    agg["rate"] = agg["sum"] / agg["count"]

    nr, nc = len(metrics), len(modes)
    cell_w, cell_h = 0.95, 0.42
    fig_w = 1.9 + nc * (len(ops) * cell_w + 0.35)
    fig_h = 1.3 + nr * (len(layers) * cell_h + 0.75)
    fig, axes = plt.subplots(nr, nc, figsize=(fig_w, fig_h), squeeze=False)

    for i, metric in enumerate(metrics):
        for j, mode in enumerate(modes):
            ax = axes[i][j]
            sub = agg[(agg.metric == metric) & (agg["mode"] == mode)]
            grid = np.full((len(layers), len(ops)), np.nan)
            text = [[""] * len(ops) for _ in layers]
            for r in sub.itertuples():
                if r.layer in layers and r.op in ops:
                    y, x = layers.index(r.layer), ops.index(r.op)
                    grid[y, x] = r.rate
                    text[y][x] = f"{r.rate:.0%}\n{int(r.sum)}/{int(r.count)}"
            # missing cells (layer had no column in any run) show as light gray
            ax.imshow(np.ma.masked_invalid(grid), cmap=SEQ, vmin=0, vmax=1,
                      aspect="auto")
            ax.set_facecolor("#f2f2f2")
            for y in range(len(layers)):
                for x in range(len(ops)):
                    v = grid[y, x]
                    ax.text(x, y, text[y][x] or "n/a", ha="center", va="center",
                            fontsize=7.5, linespacing=1.1,
                            color="white" if (v == v and v > 0.55) else INK)
            # 2px white gaps between cells
            ax.set_xticks(np.arange(-.5, len(ops)), minor=True)
            ax.set_yticks(np.arange(-.5, len(layers)), minor=True)
            ax.grid(which="minor", color="white", linewidth=2)
            ax.tick_params(which="minor", length=0)
            for s in ax.spines.values():
                s.set_visible(False)
            ax.set_xticks(range(len(ops)))
            ax.set_xticklabels(ops if i == nr - 1 else [""] * len(ops),
                               fontsize=9, color=INK2)
            ax.set_yticks(range(len(layers)))
            ax.set_yticklabels([LAYERS.get(l, l) for l in layers] if j == 0
                               else [""] * len(layers), fontsize=9, color=INK)
            ax.tick_params(length=0)
            if i == 0:
                ax.set_title(MODES.get(mode, mode), fontsize=11, color=INK,
                             fontweight="bold", pad=8)
            if j == 0:
                ax.annotate(f"Match: {METRICS[metric]}", xy=(0, 1), xycoords="axes fraction",
                            xytext=(-ax.yaxis.get_tick_padding() - 128, 6),
                            textcoords="offset points", fontsize=9.5,
                            color=INK2, ha="left", va="bottom")

    fig.suptitle(f"Detection rate by monitor layer and operation — "
                 f"{n_runs} run{'s' if n_runs != 1 else ''} pooled",
                 fontsize=13, color=INK, x=0.01, ha="left", y=0.995)
    fig.text(0.01, 0.005, "Cell: share of attempted ops the layer saw (k seen / n attempted). "
             "Darker = more visible. n/a = layer not scored in these runs.",
             fontsize=8, color=INK2, ha="left", va="bottom")
    fig.tight_layout(rect=(0, 0.02, 1, 0.97))
    fig.savefig(path, dpi=200)
    plt.close(fig)


def bars_for_metric(long, metric, layers, modes, ops, runs, path):
    """One panel per path: grouped bars per op (one per layer) = mean over runs,
    whisker = min..max over runs, small dots = each run's own rate."""
    sub = long[long.metric == metric]
    per_run = (sub.groupby(["mode", "op", "layer", "run"])["hit"]
                  .mean().reset_index(name="rate"))
    if per_run.empty:
        return False
    stats = (per_run.groupby(["mode", "op", "layer"])["rate"]
                    .agg(["mean", "min", "max"]).reset_index())

    fig, axes = plt.subplots(1, len(modes), figsize=(4.2 * len(modes) + 0.6, 4.2),
                             sharey=True, squeeze=False)
    axes = axes[0]
    group_w = 0.8
    bar_w = group_w / len(layers)
    rng = np.random.default_rng(0)            # fixed jitter → same image every time

    for j, mode in enumerate(modes):
        ax = axes[j]
        style_axes(ax)
        ax.yaxis.grid(True, color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        for k, layer in enumerate(layers):
            xs = np.arange(len(ops)) - group_w / 2 + bar_w * (k + 0.5)
            for x, op in zip(xs, ops):
                s = stats[(stats["mode"] == mode) & (stats.op == op) & (stats.layer == layer)]
                if s.empty:
                    continue
                mean, lo, hi = s.iloc[0][["mean", "min", "max"]]
                # a 0 % bar would be invisible — draw a short stub so "seen
                # nothing" reads differently from "not measured"
                h = max(mean, 0.012)
                ax.bar(x, h, width=bar_w - 0.03, color=LAYER_COLORS.get(layer, "#888"),
                       edgecolor="white", linewidth=1)
                if len(runs) > 1 and hi > lo:
                    ax.vlines(x, lo, hi, color=INK, linewidth=1)
                if len(runs) > 1:
                    pts = per_run[(per_run["mode"] == mode) & (per_run.op == op)
                                  & (per_run.layer == layer)]["rate"].to_numpy()
                    ax.scatter(x + rng.uniform(-bar_w * .18, bar_w * .18, len(pts)), pts,
                               s=11, color="white", edgecolor=INK, linewidth=0.7, zorder=3)
        ax.set_xticks(range(len(ops)))
        ax.set_xticklabels(ops, fontsize=9.5, color=INK)
        ax.set_ylim(0, 1.05)
        ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
        ax.set_title(MODES.get(mode, mode), fontsize=11, color=INK, fontweight="bold")
        if j == 0:
            ax.set_ylabel(f"Ops seen ({METRICS[metric]})", fontsize=9.5, color=INK2)

    handles = [plt.Rectangle((0, 0), 1, 1, color=LAYER_COLORS.get(l, "#888"))
               for l in layers]
    labels = [LAYERS.get(l, l) for l in layers]
    if len(runs) > 1:
        handles.append(plt.Line2D([], [], marker="o", ls="", markerfacecolor="white",
                                  markeredgecolor=INK, markersize=5))
        labels.append("one run")
    fig.legend(handles, labels, loc="upper left", ncol=len(labels), frameon=False,
               fontsize=9, bbox_to_anchor=(0.01, 0.93))
    note = (f"Bar = mean over {len(runs)} runs; whisker = min–max across runs."
            if len(runs) > 1 else "Single run.")
    fig.suptitle(f"How each monitor layer sees each operation — match: {METRICS[metric]}",
                 fontsize=13, color=INK, x=0.01, ha="left", y=0.99)
    fig.text(0.01, 0.01, note, fontsize=8, color=INK2, ha="left", va="bottom")
    fig.tight_layout(rect=(0, 0.03, 1, 0.90))
    fig.savefig(path, dpi=200)
    plt.close(fig)
    return True


# ---------------------------------------------------------- flood -----------
def flood_figure(flood_csv, path):
    """Two panels vs flood rate: (left) needle detection probability per monitor,
    (right) the monitor's event-drop %. Reads run_flood.sh's flood_raw.csv
    (per-rep), so points carry min-max spread across reps. This is the evasion
    curve: as the io_uring flood intensifies, the monitor's buffer saturates and
    a real access is seen less and less often."""
    df = pd.read_csv(flood_csv)
    need = {"monitor", "threads", "flood_rate", "drop_pct", "needle_frac"}
    missing = need - set(df.columns)
    if missing:
        print(f"skip flood plot: {flood_csv} missing {missing}", file=sys.stderr)
        return
    g = (df.groupby(["monitor", "threads"])
           .agg(rate=("flood_rate", "median"),
                detect=("needle_frac", "mean"),
                dlo=("needle_frac", "min"), dhi=("needle_frac", "max"),
                drop=("drop_pct", "median")).reset_index())

    monitors = [m for m in ("syscall", "lsm", "uring_tp", "block") if m in set(g.monitor)]
    fig, (axA, axB) = plt.subplots(1, 2, figsize=(12.4, 4.6))
    for ax in (axA, axB):
        style_axes(ax); ax.set_axisbelow(True)
        ax.yaxis.grid(True, color=GRID, linewidth=0.8)

    for m in monitors:
        sub = g[g.monitor == m].sort_values("rate")
        c = LAYER_COLORS.get(m, "#888888")
        name = LAYERS.get(m, m)
        x = sub["rate"].to_numpy()
        axA.fill_between(x, sub["dlo"], sub["dhi"], color=c, alpha=0.15, linewidth=0)
        axA.plot(x, sub["detect"], "-o", color=c, linewidth=2, markersize=5,
                 markeredgecolor="white", markeredgewidth=1, label=name)
        axB.plot(x, sub["drop"], "-o", color=c, linewidth=2, markersize=5,
                 markeredgecolor="white", markeredgewidth=1, label=name)

    axA.set_ylim(0, 1.05)
    axA.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    axA.set_ylabel("Needle detection (seen / fired)", fontsize=9.5, color=INK2)
    axA.set_title("A real access is seen less as the flood grows", fontsize=11,
                  color=INK, fontweight="bold")
    axB.set_ylim(0, 100)
    axB.set_ylabel("Monitor event-drop %", fontsize=9.5, color=INK2)
    axB.set_title("Monitor ring-buffer loss under flood", fontsize=11,
                  color=INK, fontweight="bold")
    for ax in (axA, axB):
        ax.set_xlabel("flood rate (ops/s)", fontsize=9.5, color=INK2)
        ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(
            lambda v, _: f"{v/1e6:.1f}M" if v >= 1e6 else (f"{v/1e3:.0f}k" if v else "0")))

    handles = [plt.Line2D([], [], marker="o", color=LAYER_COLORS.get(m, "#888"),
                          markeredgecolor="white", linewidth=2) for m in monitors]
    fig.legend(handles, [LAYERS.get(m, m) for m in monitors], loc="upper left",
               ncol=len(monitors), frameon=False, fontsize=9, bbox_to_anchor=(0.01, 0.98))
    fig.suptitle("Flood-evasion: saturating a monitor's ring buffer hides a real access",
                 fontsize=13, color=INK, x=0.01, ha="left", y=0.995)
    fig.text(0.01, 0.01, "Line = mean over reps; band = min-max. threads=0 (rate 0) is the "
             "no-flood control. A syscall monitor sits at 0 throughout: io_uring is invisible "
             "to it with or without a flood.", fontsize=8, color=INK2, ha="left", va="bottom")
    fig.tight_layout(rect=(0, 0.04, 1, 0.92))
    fig.savefig(path, dpi=200)
    plt.close(fig)


# ---------------------------------------------------------- cost ------------
def cost_figure(cost_csv, path):
    """Two panels for the PRIMARY (buffered) scenario: (left) throughput overhead
    % vs the no-monitor baseline, (right) events dropped per run — grouped bars,
    x = delivery mode, one bar per attached monitor. Overhead is concentrated
    where a monitor actually fires; drops show ring-buffer loss under load."""
    df = pd.read_csv(cost_csv)
    need = {"scenario", "mode", "condition", "throughput", "drops"}
    if need - set(df.columns):
        print(f"skip cost plot: {cost_csv} missing {need - set(df.columns)}", file=sys.stderr)
        return
    agg = (df.groupby(["scenario", "mode", "condition"])
             .agg(tput=("throughput", "median"), drops=("drops", "median")).reset_index())
    base = agg[agg.condition == "none"].set_index(["scenario", "mode"])["tput"].rename("base")
    agg = agg.join(base, on=["scenario", "mode"])
    agg["overhead"] = (1 - agg["tput"] / agg["base"]) * 100

    sub = agg[(agg.scenario == "primary") & (agg.condition != "none")]
    if sub.empty:
        print("skip cost plot: no primary-scenario rows", file=sys.stderr); return
    modes = [m for m in ("syscall", "uring", "sqpoll") if m in set(sub["mode"])]
    conds = [c for c in ("syscall", "lsm", "uring_tp", "block") if c in set(sub.condition)]

    def cell(m, cond, col):
        v = sub[(sub["mode"] == m) & (sub.condition == cond)][col]
        return float(v.mean()) if len(v) else 0.0

    fig, (axA, axB) = plt.subplots(1, 2, figsize=(12.4, 4.6))
    for ax in (axA, axB):
        style_axes(ax); ax.set_axisbelow(True)
        ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    group_w = 0.8; bar_w = group_w / max(len(conds), 1)
    for k, cond in enumerate(conds):
        xs = np.arange(len(modes)) - group_w / 2 + bar_w * (k + 0.5)
        c = LAYER_COLORS.get(cond, "#888888")
        axA.bar(xs, [cell(m, cond, "overhead") for m in modes], width=bar_w - 0.03,
                color=c, edgecolor="white", linewidth=1, label=LAYERS.get(cond, cond))
        axB.bar(xs, [cell(m, cond, "drops") for m in modes], width=bar_w - 0.03,
                color=c, edgecolor="white", linewidth=1, label=LAYERS.get(cond, cond))
    for ax in (axA, axB):
        ax.set_xticks(range(len(modes)))
        ax.set_xticklabels([MODES.get(m, m) for m in modes], fontsize=9.5, color=INK)
    axA.axhline(0, color=INK2, linewidth=0.8)
    axA.set_ylabel("Throughput overhead vs no monitor (%)", fontsize=9.5, color=INK2)
    axA.set_title("Cost is paid where the monitor fires", fontsize=11, color=INK, fontweight="bold")
    axB.set_ylabel("Events dropped per run", fontsize=9.5, color=INK2)
    axB.set_title("Ring-buffer loss under load", fontsize=11, color=INK, fontweight="bold")

    handles = [plt.Rectangle((0, 0), 1, 1, color=LAYER_COLORS.get(c, "#888")) for c in conds]
    fig.legend(handles, [LAYERS.get(c, c) for c in conds], loc="upper left", ncol=len(conds),
               frameon=False, fontsize=9, bbox_to_anchor=(0.01, 0.98))
    fig.suptitle("Cost of monitoring: buffered I/O, by delivery mode and monitor",
                 fontsize=13, color=INK, x=0.01, ha="left", y=0.995)
    fig.text(0.01, 0.01, "Bars = median over reps. Overhead is ~0 where a monitor does not fire for "
             "that mode (e.g. the syscall monitor under io_uring); that is also why it drops nothing there.",
             fontsize=8, color=INK2, ha="left", va="bottom")
    fig.tight_layout(rect=(0, 0.04, 1, 0.92))
    fig.savefig(path, dpi=200); plt.close(fig)


# ---------------------------------------------------------- main ------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="*", help="detection run folders / per_op.csv files / globs, optionally label=path")
    ap.add_argument("--outdir", default="figures")
    ap.add_argument("--ops", help="comma-separated op order, e.g. open,read,write,append")
    ap.add_argument("--flood", help="run_flood.sh's flood_raw.csv — adds the flood-evasion figure")
    ap.add_argument("--cost", help="run_cost.sh's cost_raw.csv — adds the cost/overhead figure")
    args = ap.parse_args()

    if not args.runs and not args.flood and not args.cost:
        sys.exit("pass detection run folders and/or --flood <flood_raw.csv> and/or --cost <cost_raw.csv>")
    os.makedirs(args.outdir, exist_ok=True)

    if args.runs:
        runs = resolve_runs(args.runs)
        long = load_long(runs)
        layers = ordered(long.layer, list(LAYERS))
        modes = ordered(long["mode"], list(MODES))
        ops = args.ops.split(",") if args.ops else ordered(long.op, ["open", "read", "write", "append"])
        metrics = [m for m in METRICS if m in set(long.metric)]
        print(f"runs ({len(runs)}): " + ", ".join(f"{n} [{c}]" for n, c in runs))
        print(f"layers: {layers}\npaths:  {modes}\nops:    {ops}\nmetrics: {metrics}")

        table = (long.groupby(["run", "layer", "mode", "op", "metric"])["hit"]
                     .agg(seen="sum", attempted="count").reset_index())
        table["rate"] = table.seen / table.attempted
        table.to_csv(os.path.join(args.outdir, "combined_long.csv"), index=False)

        heatmap_grid(long, layers, modes, ops, metrics, len(runs),
                     os.path.join(args.outdir, "heatmap_all_runs.png"))
        for m in metrics:
            bars_for_metric(long, m, layers, modes, ops, runs,
                            os.path.join(args.outdir, f"bars_{m}.png"))
        print(f"wrote heatmap_all_runs.png, bars_<metric>.png, combined_long.csv to {args.outdir}/")

    if args.flood:
        flood_figure(args.flood, os.path.join(args.outdir, "flood_evasion.png"))
        print(f"wrote flood_evasion.png to {args.outdir}/")

    if args.cost:
        cost_figure(args.cost, os.path.join(args.outdir, "cost_overhead.png"))
        print(f"wrote cost_overhead.png to {args.outdir}/")


if __name__ == "__main__":
    main()