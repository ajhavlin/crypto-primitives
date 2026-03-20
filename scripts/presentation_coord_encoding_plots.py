#!/usr/bin/env python3
"""Generate presentation-style proof-size figures for coordinate encoding comparisons.

Usage:
    python3 scripts/presentation_coord_encoding_plots.py         --input target/merkle_tree_reports/coordinate_encoding_rows.csv         --output figures/presentation
    python3 scripts/presentation_coord_encoding_plots.py         --input target/merkle_tree_reports/leb128_vs_delta_rows.csv         --output figures/presentation
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


DEFAULT_LABELS = {
    "natural": "Unoptimized",
    "leb128": "Partially Optimized",
    "delta": "Optimized",
}

DEFAULT_COLORS = {
    "natural": "#d95f02",
    "leb128": "#1b9e77",
    "delta": "#1f77b4",
}

DEFAULT_MARKERS = {
    "natural": "s",
    "leb128": "o",
    "delta": "^",
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


def resolve_input_path(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit

    candidates = [
        Path("target/merkle_tree_reports/coordinate_encoding_rows.csv"),
        Path("target/merkle_tree_reports/coordinate_encoding_report.md"),
        Path("target/merkle_tree_reports/leb128_vs_delta_rows.csv"),
        Path("target/merkle_tree_reports/leb128_vs_delta_report.md"),
        Path("crypto-primitives/target/merkle_tree_reports/coordinate_encoding_rows.csv"),
        Path("crypto-primitives/target/merkle_tree_reports/coordinate_encoding_report.md"),
        Path("crypto-primitives/target/merkle_tree_reports/leb128_vs_delta_rows.csv"),
        Path("crypto-primitives/target/merkle_tree_reports/leb128_vs_delta_report.md"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "No coordinate encoding input found under target/merkle_tree_reports "
        "or crypto-primitives/target/merkle_tree_reports."
    )


def read_rows_csv(path: Path) -> List[Row]:
    rows: List[Row] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(
                Row(
                    tree_size=int(row["tree_size"]),
                    log2_size=int(row["log2_size"]),
                    batch=int(row["batch"]),
                    pattern=row["pattern"],
                    strategy=row["strategy"],
                    proof_bytes=int(row["proof_bytes"]),
                    proof_nodes=int(row["proof_nodes"]),
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
                )
            )

    return rows


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


def infer_strategy_order(rows: Sequence[Row]) -> List[str]:
    strategies = sorted({row.strategy for row in rows})
    if strategies == ["leb128", "natural"]:
        return ["natural", "leb128"]
    if strategies == ["delta", "leb128"]:
        return ["leb128", "delta"]
    preferred = [name for name in ["natural", "leb128", "delta"] if name in strategies]
    return preferred + [name for name in strategies if name not in preferred]


def label_for(strategy: str) -> str:
    return DEFAULT_LABELS.get(strategy, strategy)


def color_for(strategy: str) -> str:
    return DEFAULT_COLORS.get(strategy, "#000000")


def marker_for(strategy: str) -> str:
    return DEFAULT_MARKERS.get(strategy, "o")


def filename_prefix_for(strategies: Sequence[str]) -> str:
    ordered = list(strategies)
    if ordered == ["natural", "leb128"]:
        return "coordinate_proof_size"
    if ordered == ["leb128", "delta"]:
        return "leb128_vs_delta_proof_size"
    return "coord_comparison_proof_size"


def generate_plot(
    rows: Sequence[Row],
    pattern: str,
    tree_size: int,
    selected_k: Sequence[int],
    output_dir: Path,
    strategy_order: Sequence[str],
) -> List[Path]:
    by_strategy: Dict[str, Dict[int, float]] = defaultdict(dict)
    for row in rows:
        if row.pattern != pattern or row.tree_size != tree_size:
            continue
        by_strategy[row.strategy][row.batch] = float(row.proof_bytes)

    fig, ax = plt.subplots(figsize=(13.33, 7.5), dpi=300)

    raw_values = [value for points in by_strategy.values() for value in points.values()]
    unit_scale, unit_prefix = choose_byte_unit(raw_values)

    all_points: List[Tuple[int, float, str]] = []
    for strategy in strategy_order:
        points = by_strategy.get(strategy, {})
        xs = [k for k in selected_k if k in points]
        ys = [points[k] / unit_scale for k in xs]
        if not xs:
            continue
        ax.plot(
            xs,
            ys,
            label=label_for(strategy),
            color=color_for(strategy),
            marker=marker_for(strategy),
            linewidth=3.0,
            markersize=9,
        )
        for x, y in zip(xs, ys):
            all_points.append((x, y, strategy))

    if not all_points:
        plt.close(fig)
        return []

    y_values = [p[1] for p in all_points]
    ymin = min(y_values)
    ymax = max(y_values)
    yrange = max(ymax - ymin, ymax * 0.08, 1e-9)

    ax.set_xscale("log", base=2)
    ax.set_xticks(list(selected_k))
    ax.set_xticklabels([str(x) for x in selected_k])
    ax.set_xlim(min(selected_k) * 0.9, max(selected_k) * 1.15)
    ax.set_ylim(max(0.0, ymin - 0.10 * yrange), ymax + 0.14 * yrange)
    ax.set_xlabel("Number of leaves opened", labelpad=10, fontname="Helvetica Neue", fontweight="bold")
    ax.set_ylabel(
        proof_size_label(unit_prefix),
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

    basename = f"{filename_prefix_for(strategy_order)}_vs_k_{pattern}"
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

    available_tree_sizes = sorted({row.tree_size for row in rows})
    tree_size = args.tree_size if args.tree_size is not None else available_tree_sizes[-1]
    if tree_size not in available_tree_sizes:
        raise ValueError(f"tree_size {tree_size} not present. Available: {available_tree_sizes}")

    output_dir = args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"input={input_path}")

    strategy_order = infer_strategy_order(rows)
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

    for pattern, (selected_k, _, _) in pattern_to_selection.items():
        scoped_rows = [row for row in rows if row.tree_size == tree_size and row.pattern == pattern]
        files = generate_plot(
            rows=scoped_rows,
            pattern=pattern,
            tree_size=tree_size,
            selected_k=selected_k,
            output_dir=output_dir,
            strategy_order=strategy_order,
        )
        if files:
            print(f"generated={ [str(path) for path in files] }")


if __name__ == "__main__":
    main()
