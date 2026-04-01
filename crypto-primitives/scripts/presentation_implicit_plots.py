#!/usr/bin/env python3
"""Generate presentation-style figures comparing CoSet (with coordinates) vs Implicit (coord-free).

Data flow:
1) Run the Rust benchmark test:
       cargo test --features bench_harness,merkle_tree -- --ignored --nocapture implicit_vs_coset_report
2) This writes target/merkle_tree_reports/implicit_vs_coset_rows.csv
3) Run this script:
       python3 scripts/presentation_implicit_plots.py
   Output goes to figures/presentation/ as PNG, PDF, and SVG.

The script generates one figure per metric (proof_bytes, prove_ms, verify_ms) per pattern
(clustered, random), with both strategies on the same axes in different colours.
"""

from __future__ import annotations

import argparse
import csv
import os
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Row:
    tree_size: int
    log2_size: int
    batch: int
    pattern: str
    strategy: str
    proof_bytes: int
    proof_nodes: int
    hashes_per_opening: float
    prove_ms: float
    verify_ms: float


@dataclass(frozen=True)
class MetricSpec:
    key: str
    title: str
    y_label: str
    filename_prefix: str


METRICS: Tuple[MetricSpec, ...] = (
    MetricSpec("proof_bytes", "Proof Size vs Input Size", "Proof size (kB)", "proof_size"),
    MetricSpec("prove_ms", "Prover Time vs Input Size", "Time (ms)", "prover_time"),
    MetricSpec("verify_ms", "Verifier Time vs Input Size", "Time (ms)", "verifier_time"),
)

# Colour and marker choices:
#   coset   — blue  (same shade used in presentation_plots.py for "New/coset")
#   implicit — purple (distinct; dark enough to remain legible in greyscale)
STRATEGY_STYLE: Dict[str, dict] = {
    "coset": {
        "label": "CoSet (delta coords)",
        "color": "#1f77b4",
        "marker": "o",
        "zorder": 3,
    },
    "implicit": {
        "label": "Implicit (coord-free)",
        "color": "#7b35c1",
        "marker": "^",
        "zorder": 4,
    },
}

DRAW_ORDER = ["coset", "implicit"]
PRESENTATION_X_TICKS = [1, 8, 64, 512, 4096]


def ensure_slide_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "Helvetica Neue",
            "svg.fonttype": "none",
            "figure.titlesize": 30,
            "axes.titlesize": 28,
            "axes.labelsize": 24,
            "xtick.labelsize": 18,
            "ytick.labelsize": 18,
            "legend.fontsize": 17,
        }
    )


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("target/merkle_tree_reports/implicit_vs_coset_rows.csv"),
        help="CSV produced by the implicit_vs_coset_report bench test",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("figures/presentation"),
        help="Directory where figures are written",
    )
    parser.add_argument(
        "--patterns",
        nargs="+",
        default=["clustered", "random"],
        help="Query patterns to render (default: clustered random)",
    )
    parser.add_argument(
        "--tree-size",
        type=int,
        default=None,
        help="Specific tree size n to plot. Default: largest n in the dataset",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# CSV loading
# ---------------------------------------------------------------------------

def load_csv(path: Path) -> List[Row]:
    rows: List[Row] = []
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        for raw in reader:
            rows.append(
                Row(
                    tree_size=int(raw["tree_size"]),
                    log2_size=int(raw["log2_size"]),
                    batch=int(raw["batch"]),
                    pattern=raw["pattern"],
                    strategy=raw["strategy"],
                    proof_bytes=int(raw["proof_bytes"]),
                    proof_nodes=int(raw["proof_nodes"]),
                    hashes_per_opening=float(raw["hashes_per_opening"]),
                    prove_ms=float(raw["prove_ms"]),
                    verify_ms=float(raw["verify_ms"]),
                )
            )
    return rows


# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------

def _get_metric_value(row: Row, metric: MetricSpec) -> float:
    value = float(getattr(row, metric.key))
    if metric.key == "proof_bytes":
        return value / 1024.0
    return value


def _format_y_tick(metric: MetricSpec) -> ticker.Formatter:
    if metric.key == "proof_bytes":
        return ticker.FuncFormatter(
            lambda v, _: f"{v:,.0f}" if v >= 100 else f"{v:,.1f}".rstrip("0").rstrip(".")
        )
    return ticker.FuncFormatter(
        lambda v, _: f"{v:,.2f}".rstrip("0").rstrip(".") if abs(v) < 100 else f"{v:,.0f}"
    )


def plot_metric_pattern(
    rows: List[Row],
    metric: MetricSpec,
    pattern: str,
    tree_size: int,
    out_dir: Path,
) -> List[Path]:
    """Render one figure for (metric, pattern) and write PNG/PDF/SVG."""
    ensure_slide_style()

    subset = [
        r for r in rows if r.pattern == pattern and r.tree_size == tree_size
    ]
    if not subset:
        return []

    # Group by strategy
    series: Dict[str, List[Tuple[int, float]]] = defaultdict(list)
    for row in subset:
        if row.batch in PRESENTATION_X_TICKS:
            series[row.strategy].append((row.batch, _get_metric_value(row, metric)))

    for strat in series:
        series[strat].sort()

    fig, ax = plt.subplots(figsize=(13.33, 7.5), dpi=300)
    available_x_values = sorted({batch for points in series.values() for batch, _ in points})
    x_ticks = [x for x in PRESENTATION_X_TICKS if x in available_x_values]

    if not x_ticks:
        plt.close(fig)
        return []

    for strat in DRAW_ORDER:
        if strat not in series:
            continue
        style = STRATEGY_STYLE[strat]
        xs = [p[0] for p in series[strat]]
        ys = [p[1] for p in series[strat]]
        ax.plot(
            xs,
            ys,
            color=style["color"],
            marker=style["marker"],
            label=style["label"],
            linewidth=3.0,
            markersize=9,
            zorder=style["zorder"],
        )

    all_points = [(x, y) for points in series.values() for x, y in points]
    y_values = [y for _, y in all_points]
    ymin = min(y_values)
    ymax = max(y_values)
    yrange = max(ymax - ymin, ymax * 0.08, 1e-9)

    ax.set_xlabel(
        "Number of leaves opened",
        labelpad=10,
        fontname="Helvetica Neue",
        fontweight="bold",
    )
    ax.set_ylabel(
        metric.y_label,
        labelpad=10,
        fontname="Helvetica Neue",
        fontweight="bold",
    )
    ax.set_xscale("log", base=2)
    ax.set_xticks(x_ticks)
    ax.set_xticklabels([str(x) for x in x_ticks])
    ax.set_xlim(min(x_ticks) * 0.9, max(x_ticks) * 1.15)
    ax.set_ylim(max(0.0, ymin - 0.10 * yrange), ymax + 0.14 * yrange)
    ax.xaxis.set_minor_locator(ticker.NullLocator())
    ax.yaxis.set_major_locator(ticker.MaxNLocator(nbins=6))
    ax.yaxis.set_major_formatter(_format_y_tick(metric))
    legend = ax.legend(
        loc="upper left",
        bbox_to_anchor=(1.02, 1.0),
        borderaxespad=0.0,
        frameon=False,
    )
    if legend is not None:
        for legend_text in legend.get_texts():
            legend_text.set_fontfamily("Helvetica Neue")
            legend_text.set_fontweight("bold")

    for tick_label in ax.get_xticklabels() + ax.get_yticklabels():
        tick_label.set_fontfamily("Helvetica Neue")

    ax.grid(True, which="major", linestyle="--", alpha=0.28)
    fig.tight_layout()

    stem = f"implicit_vs_coset_{metric.filename_prefix}_vs_k_{pattern}"
    written: List[Path] = []
    for ext in ("png", "pdf", "svg"):
        dest = out_dir / f"{stem}.{ext}"
        save_kwargs = {"bbox_inches": "tight"}
        if ext == "png":
            save_kwargs["dpi"] = 300
        fig.savefig(dest, **save_kwargs)
        written.append(dest)

    plt.close(fig)
    return written


def main() -> None:
    args = parse_args()

    if not args.input.exists():
        raise SystemExit(
            f"Input file not found: {args.input}\n"
            "Run the Rust benchmark first:\n"
            "  cargo test --features bench_harness,merkle_tree -- "
            "--ignored --nocapture implicit_vs_coset_report"
        )

    rows = load_csv(args.input)
    if not rows:
        raise SystemExit(f"No rows found in {args.input}")

    tree_size = args.tree_size or max(r.tree_size for r in rows)
    args.output.mkdir(parents=True, exist_ok=True)

    all_written: List[Path] = []
    for metric in METRICS:
        for pattern in args.patterns:
            written = plot_metric_pattern(rows, metric, pattern, tree_size, args.output)
            all_written.extend(written)

    for p in all_written:
        print(f"Wrote {p}")

    if not all_written:
        print("No figures generated — check that the CSV contains matching rows.")


if __name__ == "__main__":
    main()
