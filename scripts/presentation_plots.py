#!/usr/bin/env python3
"""Generate presentation-friendly figures from multiproof benchmark rows.

Data flow (existing benchmark path):
1) Rust benchmark test builds trees, samples (k, pattern), and benchmarks prefix/coset.
2) The test writes either raw rows CSV (multiproof_v2_rows.csv) and/or markdown report table
   (multiproof_v2_report.md) under target/merkle_tree_reports/.
3) This script reads those rows and renders one figure per metric/pattern in
   figures/presentation/, using a representative subset of k values.

Usage:
    python3 scripts/presentation_plots.py
    python3 scripts/presentation_plots.py \
        --input target/merkle_tree_reports/multiproof_v2_report.md \
        --output figures/presentation
"""

from __future__ import annotations

import argparse
import csv
import math
import os
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

# Matplotlib needs a writable config dir in some sandboxed environments.
os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")

import matplotlib.pyplot as plt


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
    rss_delta_kb: float | None


@dataclass(frozen=True)
class MetricSpec:
    key: str
    title: str
    y_label: str
    filename_prefix: str


METRICS: Tuple[MetricSpec, ...] = (
    MetricSpec("proof_bytes", "Proof Size vs Input Size", "Proof size (bytes)", "proof_size"),
    MetricSpec("prove_ms", "Prover Time vs Input Size", "Time (ms)", "prover_time"),
    MetricSpec("verify_ms", "Verifier Time vs Input Size", "Time (ms)", "verifier_time"),
    MetricSpec(
        "hashes_per_opening",
        "Hashes per Opening (m Proxy) vs Input Size",
        "Hashes per opening",
        "hashes_per_opening",
    ),
)

STRATEGY_STYLE = {
    "prefix": {"label": "Old", "color": "#d62728", "marker": "s"},
    "coset": {"label": "New", "color": "#1f77b4", "marker": "o"},
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Optional input file (.csv rows or .md report table). Auto-detected if omitted.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("figures/presentation"),
        help="Directory where presentation figures are written",
    )
    parser.add_argument(
        "--patterns",
        nargs="+",
        default=["clustered", "random"],
        help="Patterns to render (default: clustered random)",
    )
    parser.add_argument(
        "--tree-size",
        type=int,
        default=None,
        help="Specific tree size n to plot. Default: max n in dataset",
    )
    parser.add_argument(
        "--points",
        type=int,
        default=5,
        help="Representative k points per plot",
    )
    return parser.parse_args()


def read_rows_csv(path: Path) -> List[Row]:
    rows: List[Row] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for r in reader:
            rss_raw = (r.get("rss_delta_kb") or "").strip()
            rows.append(
                Row(
                    tree_size=int(r["tree_size"]),
                    log2_size=int(r["log2_size"]),
                    batch=int(r["batch"]),
                    pattern=r["pattern"],
                    strategy=r["strategy"],
                    proof_bytes=int(r["proof_bytes"]),
                    proof_nodes=int(r["proof_nodes"]),
                    hashes_per_opening=float(r["hashes_per_opening"]),
                    prove_ms=float(r["prove_ms"]),
                    verify_ms=float(r["verify_ms"]),
                    rss_delta_kb=float(rss_raw) if rss_raw else None,
                )
            )
    return rows


def read_rows_markdown(path: Path) -> List[Row]:
    rows: List[Row] = []
    headers: List[str] = []

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.startswith("|"):
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if not cells:
                continue
            if cells[0] == "tree_n":
                headers = cells
                continue
            if cells[0].startswith("------") or not headers:
                continue
            if len(cells) != len(headers):
                continue

            row = dict(zip(headers, cells))
            rows.append(
                Row(
                    tree_size=int(row["tree_n"]),
                    log2_size=int(row["log2(n)"]),
                    batch=int(row["batch_k"]),
                    pattern=row["pattern"],
                    strategy=row["strategy"],
                    proof_bytes=int(row["proof_bytes"]),
                    proof_nodes=int(row["proof_nodes"]),
                    hashes_per_opening=float(row["hashes/leaf"]),
                    prove_ms=float(row["prove_ms"]),
                    verify_ms=float(row["verify_ms"]),
                    rss_delta_kb=float(row["rss_delta_kb"]) if row["rss_delta_kb"] != "-" else None,
                )
            )

    return rows


def resolve_input_path(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit

    candidates = [
        Path("target/merkle_tree_reports/multiproof_v2_rows.csv"),
        Path("target/merkle_tree_reports/multiproof_v2_report.md"),
        Path("crypto-primitives/target/merkle_tree_reports/multiproof_v2_rows.csv"),
        Path("crypto-primitives/target/merkle_tree_reports/multiproof_v2_report.md"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "No benchmark input found. Looked for multiproof_v2_rows.csv or multiproof_v2_report.md "
        "under target/merkle_tree_reports and crypto-primitives/target/merkle_tree_reports."
    )


def metric_value(row: Row, metric_key: str) -> float:
    return float(getattr(row, metric_key))


def representative_values(values: Sequence[int], count: int) -> Tuple[List[int], List[Tuple[float, int]]]:
    unique = sorted(set(values))
    if not unique:
        return [], []
    if len(unique) <= count:
        return unique, [(float(v), v) for v in unique]

    vmin = unique[0]
    vmax = unique[-1]
    log_min = math.log(vmin)
    log_max = math.log(vmax)

    targets = []
    for i in range(count):
        t = math.exp(log_min + (log_max - log_min) * (i / (count - 1)))
        targets.append(t)

    selected: List[int] = []
    selections: List[Tuple[float, int]] = []

    for target in targets:
        remaining = [v for v in unique if v not in selected]
        if not remaining:
            break
        choice = min(remaining, key=lambda v: abs(math.log(v) - math.log(target)))
        selected.append(choice)
        selections.append((target, choice))

    if unique[0] not in selected:
        selected[0] = unique[0]
    if unique[-1] not in selected:
        selected[-1] = unique[-1]

    selected = sorted(set(selected))
    if len(selected) < count:
        for v in unique:
            if v not in selected:
                selected.append(v)
                if len(selected) == count:
                    break
    selected = sorted(selected)

    mapped_targets = []
    for t in targets:
        mapped_targets.append((t, min(selected, key=lambda v: abs(math.log(v) - math.log(t)))))

    return selected, mapped_targets


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


def generate_plot(
    rows: Sequence[Row],
    metric: MetricSpec,
    pattern: str,
    tree_size: int,
    selected_k: Sequence[int],
    output_dir: Path,
    shared_y_range: Tuple[float, float] | None = None,
) -> List[Path]:
    by_strategy: Dict[str, Dict[int, float]] = defaultdict(dict)
    for row in rows:
        if row.pattern != pattern or row.tree_size != tree_size:
            continue
        by_strategy[row.strategy][row.batch] = metric_value(row, metric.key)

    fig, ax = plt.subplots(figsize=(13.33, 7.5), dpi=300)

    all_points: List[Tuple[int, float, str]] = []
    unit_scale = 1.0
    unit_prefix = ""
    if metric.key == "proof_bytes":
        raw_values = list(by_strategy.get("prefix", {}).values()) + list(by_strategy.get("coset", {}).values())
        unit_scale, unit_prefix = choose_byte_unit(raw_values)

    for strategy in ("prefix", "coset"):
        points = by_strategy.get(strategy, {})
        xs = [k for k in selected_k if k in points]
        ys = [points[k] / unit_scale for k in xs]
        if not xs:
            continue
        style = STRATEGY_STYLE.get(strategy, {"label": strategy, "color": "#000000", "marker": "o"})
        ax.plot(
            xs,
            ys,
            label=style["label"],
            color=style["color"],
            marker=style["marker"],
            linewidth=3.0,
            markersize=9,
        )
        for x, y in zip(xs, ys):
            all_points.append((x, y, strategy))

    if not all_points:
        plt.close(fig)
        return []

    if shared_y_range is None:
        y_values = [p[1] for p in all_points]
        ymin = min(y_values)
        ymax = max(y_values)
    else:
        ymin, ymax = shared_y_range
        ymin /= unit_scale
        ymax /= unit_scale
    yrange = max(ymax - ymin, ymax * 0.08, 1e-9)

    ax.set_xscale("log", base=2)
    ax.set_xticks(list(selected_k))
    ax.set_xticklabels([str(x) for x in selected_k])
    ax.set_xlim(min(selected_k) * 0.9, max(selected_k) * 1.15)
    ax.set_ylim(max(0.0, ymin - 0.10 * yrange), ymax + 0.14 * yrange)
    ax.set_xlabel("Number of leaves opened", labelpad=10, fontname="Helvetica Neue", fontweight="bold")
    ax.set_ylabel(
        proof_size_label(unit_prefix) if metric.key == "proof_bytes" else metric.y_label,
        labelpad=10,
        fontname="Helvetica Neue",
        fontweight="bold",
    )
    ax.grid(True, which="major", linestyle="--", alpha=0.28)

    legend = ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1.0), frameon=False)
    if legend is not None:
        for legend_text in legend.get_texts():
            legend_text.set_fontfamily("Helvetica Neue")
            legend_text.set_fontweight("bold")

    for tick_label in ax.get_xticklabels() + ax.get_yticklabels():
        tick_label.set_fontfamily("Helvetica Neue")

    fig.tight_layout()

    basename = f"{metric.filename_prefix}_vs_k_{pattern}"
    outputs = []
    for ext in ("png", "pdf", "svg"):
        out_path = output_dir / f"{basename}.{ext}"
        save_kwargs = {"bbox_inches": "tight"}
        if ext == "png":
            save_kwargs["dpi"] = 300
        fig.savefig(out_path, **save_kwargs)
        outputs.append(out_path)

    plt.close(fig)
    return outputs


def compute_shared_y_ranges(
    rows: Sequence[Row],
    tree_size: int,
    pattern_to_selection: Dict[str, Tuple[List[int], List[Tuple[float, int]], List[int]]],
    metrics: Sequence[MetricSpec],
) -> Dict[str, Tuple[float, float]]:
    ranges: Dict[str, Tuple[float, float]] = {}
    patterns = set(pattern_to_selection.keys())

    for metric in metrics:
        values: List[float] = []
        for row in rows:
            if row.tree_size != tree_size or row.pattern not in patterns:
                continue
            selected_k = pattern_to_selection[row.pattern][0]
            if row.batch not in selected_k:
                continue
            values.append(metric_value(row, metric.key))

        if values:
            ranges[metric.key] = (min(values), max(values))

    return ranges


def choose_byte_unit(values: Sequence[float]) -> Tuple[float, str]:
    if not values:
        return 1.0, ""

    max_abs = max(abs(v) for v in values)
    if max_abs >= 1_000_000_000:
        return 1_000_000_000.0, "G"
    if max_abs >= 1_000_000:
        return 1_000_000.0, "M"
    if max_abs >= 1_000:
        return 1_000.0, "k"
    return 1.0, ""


def proof_size_label(prefix: str) -> str:
    units = {
        "": "B",
        "k": "kB",
        "M": "MB",
        "G": "GB",
    }
    return f"Proof size ({units[prefix]})"


def write_selection_summary(
    output_dir: Path,
    tree_size: int,
    pattern_to_selection: Dict[str, Tuple[List[int], List[Tuple[float, int]], List[int]]],
) -> None:
    summary_path = output_dir / "selection_summary.txt"
    with summary_path.open("w", encoding="utf-8") as handle:
        handle.write(f"tree_size={tree_size}\n")
        for pattern, (selected, mapping, available) in pattern_to_selection.items():
            handle.write(f"\npattern={pattern}\n")
            handle.write(f"available_k={available}\n")
            handle.write(f"selected_k={selected}\n")
            handle.write("targets_to_selected=\n")
            for target, chosen in mapping:
                handle.write(f"  target~{target:.2f} -> {chosen}\n")


def average(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / float(len(values))


def write_highest_k_differences(
    output_dir: Path,
    rows: Sequence[Row],
    tree_size: int,
    patterns: Sequence[str],
) -> None:
    summary_path = output_dir / "largest_k_percent_change.txt"
    lines: List[str] = [f"tree_size={tree_size}"]

    metric_specs = [
        ("proof_bytes", "proof size"),
        ("prove_ms", "prover time"),
        ("verify_ms", "verifier time"),
    ]

    for pattern in patterns:
        scoped = [r for r in rows if r.tree_size == tree_size and r.pattern == pattern]
        if not scoped:
            continue

        by_strategy: Dict[str, Dict[int, List[Row]]] = defaultdict(lambda: defaultdict(list))
        for row in scoped:
            by_strategy[row.strategy][row.batch].append(row)

        if "prefix" not in by_strategy or "coset" not in by_strategy:
            continue

        shared_k = sorted(set(by_strategy["prefix"].keys()) & set(by_strategy["coset"].keys()))
        if not shared_k:
            continue

        highest_k = shared_k[-1]
        lines.append(f"")
        lines.append(f"pattern={pattern}")
        lines.append(f"largest_k={highest_k}")

        for metric_key, label in metric_specs:
            prefix_values = [metric_value(r, metric_key) for r in by_strategy["prefix"][highest_k]]
            coset_values = [metric_value(r, metric_key) for r in by_strategy["coset"][highest_k]]
            if not prefix_values or not coset_values:
                continue

            old_avg = average(prefix_values)
            new_avg = average(coset_values)
            pct = 0.0 if old_avg == 0 else ((new_avg - old_avg) / old_avg) * 100.0
            lines.append(f"{label}: {pct:+.2f}% (Old={old_avg:.3f}, New={new_avg:.3f})")

    with summary_path.open("w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main() -> None:
    args = parse_args()
    ensure_slide_style()

    input_path = resolve_input_path(args.input)
    if input_path.suffix.lower() == ".csv":
        rows = read_rows_csv(input_path)
    elif input_path.suffix.lower() == ".md":
        rows = read_rows_markdown(input_path)
    else:
        raise ValueError(f"Unsupported input format: {input_path}")

    if not rows:
        raise RuntimeError(f"No benchmark rows found in {input_path}")

    available_tree_sizes = sorted({r.tree_size for r in rows})
    tree_size = args.tree_size if args.tree_size is not None else available_tree_sizes[-1]
    if tree_size not in available_tree_sizes:
        raise ValueError(f"tree_size {tree_size} not present. Available: {available_tree_sizes}")

    output_dir = args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"input={input_path}")

    pattern_to_selection: Dict[str, Tuple[List[int], List[Tuple[float, int]], List[int]]] = {}

    for pattern in args.patterns:
        strategy_batches: Dict[str, List[int]] = defaultdict(list)
        for row in rows:
            if row.tree_size == tree_size and row.pattern == pattern:
                strategy_batches[row.strategy].append(row.batch)

        if not strategy_batches:
            print(f"Skipping pattern={pattern}: no rows for tree_size={tree_size}")
            continue

        shared = sorted(set.intersection(*(set(v) for v in strategy_batches.values())))
        if not shared:
            print(f"Skipping pattern={pattern}: no shared k across strategies")
            continue

        selected_k, target_map = representative_values(shared, args.points)
        pattern_to_selection[pattern] = (selected_k, target_map, shared)

        print(f"pattern={pattern} tree_size={tree_size} available_k={shared}")
        print(f"pattern={pattern} selected_k={selected_k}")

    shared_y_ranges = compute_shared_y_ranges(
        rows=rows,
        tree_size=tree_size,
        pattern_to_selection=pattern_to_selection,
        metrics=METRICS,
    )

    for pattern, (selected_k, _, _) in pattern_to_selection.items():
        scoped_rows = [r for r in rows if r.tree_size == tree_size and r.pattern == pattern]
        for metric in METRICS:
            files = generate_plot(
                scoped_rows,
                metric,
                pattern,
                tree_size,
                selected_k,
                output_dir,
                shared_y_range=None if metric.key in {"proof_bytes", "prove_ms", "verify_ms"} else shared_y_ranges.get(metric.key),
            )
            if files:
                print(f"regenerated(shared-y): {[str(f) for f in files]}")

    write_selection_summary(output_dir, tree_size, pattern_to_selection)
    write_highest_k_differences(
        output_dir=output_dir,
        rows=rows,
        tree_size=tree_size,
        patterns=list(pattern_to_selection.keys()),
    )


if __name__ == "__main__":
    main()
