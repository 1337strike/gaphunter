"""Reporting: ATT&CK Navigator layers, IEEE-style figures, LaTeX tables, CSV exports.

Everything is rebuilt from the files in ``<run>/eval``, so ``gaphunter report`` can be
re-run (for example after editing ``configs/techniques.yaml``) without re-evaluating.

Figures are vector PDF, 3.5 in wide (one IEEE column), 8 pt serif, with TrueType fonts
embedded. Detectors keep one colour everywhere; bars also carry hatching and lines carry
distinct dash patterns so the figures survive greyscale printing.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from gaphunter.attack import TACTIC_ORDER, tactic_label
from gaphunter.errors import GapHunterError
from gaphunter.log import get_logger
from gaphunter.rundir import RunDir

log = get_logger(__name__)

COLUMN_WIDTH_IN = 3.5

# One colour per detector, fixed (validated categorical palette, in slot order).
DETECTOR_COLORS: dict[str, str] = {
    "rule": "#2a78d6",
    "iforest": "#eb6834",
    "autoencoder": "#1baf7a",
    "ocsvm": "#eda100",
    "hybrid": "#e87ba4",
}
DETECTOR_HATCH: dict[str, str] = {
    "rule": "",
    "iforest": "..",
    "autoencoder": "///",
    "ocsvm": "xx",
    "hybrid": "\\\\\\",
}
DETECTOR_DASH: dict[str, Any] = {
    "rule": "-",
    "iforest": (0, (4, 1.5)),
    "autoencoder": (0, (1, 1)),
    "ocsvm": (0, (4, 1, 1, 1)),
    "hybrid": (0, (6, 2)),
}
DETECTOR_NAMES: dict[str, str] = {
    "rule": "Sigma rules",
    "iforest": "Isolation Forest",
    "autoencoder": "Autoencoder",
    "ocsvm": "One-Class SVM",
}
DETECTOR_SHORT: dict[str, str] = {
    "rule": "Rules",
    "iforest": "IF",
    "autoencoder": "AE",
    "ocsvm": "OC-SVM",
}
SEQUENTIAL = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
INK, INK_SECONDARY, MUTED, GRID, AXIS = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
GAP_COLORS: dict[str, str] = {
    "both": "#2a78d6",
    "rule_only": "#eb6834",
    "ml_only": "#1baf7a",
    "neither": "#e34948",
    "no_telemetry": "#c3c2b7",
}
GAP_LABELS: dict[str, str] = {
    "both": "Detected by rules and ML",
    "rule_only": "Rules only",
    "ml_only": "ML only (gap closed)",
    "neither": "Missed by both",
    "no_telemetry": "No telemetry",
}
SYNTHETIC_NOTE = "SYNTHETIC DEMO DATA - NOT RESULTS"


def detector_key(detector: str) -> str:
    return "hybrid" if detector.startswith("hybrid_") else detector


def detector_short(detector: str) -> str:
    """Compact label for narrow figures (Rules, IF, AE, OC-SVM, Rules+AE)."""
    if detector.startswith("hybrid_"):
        return "Rules+" + DETECTOR_SHORT.get(detector.removeprefix("hybrid_"), detector)
    return DETECTOR_SHORT.get(detector, detector)


def detector_name(detector: str) -> str:
    if detector.startswith("hybrid_"):
        return "Rules + " + DETECTOR_NAMES.get(detector.removeprefix("hybrid_"), detector)
    return DETECTOR_NAMES.get(detector, detector)


# -- loading -------------------------------------------------------------------------


def load_eval(run: RunDir) -> dict[str, Any]:
    directory = run.eval_dir
    needed = ["metrics.json", "detector_metrics.csv", "technique_detection.csv"]
    if not all((directory / name).is_file() for name in needed):
        raise GapHunterError("evaluation results not found; run 'gaphunter evaluate' first")
    tactics_path = directory / "tactic_coverage.csv"
    try:
        tactics = pd.read_csv(tactics_path)
    except (FileNotFoundError, pd.errors.EmptyDataError):
        tactics = pd.DataFrame(
            columns=["tactic", "detector", "n_techniques", "n_detected", "coverage"]
        )
    curves_path = directory / "curves.json"
    return {
        "summary": json.loads((directory / "metrics.json").read_text(encoding="utf-8")),
        "detectors": pd.read_csv(directory / "detector_metrics.csv"),
        "techniques": pd.read_csv(directory / "technique_detection.csv"),
        "tactics": tactics,
        "curves": json.loads(curves_path.read_text(encoding="utf-8"))
        if curves_path.is_file()
        else {},
    }


def headline_detectors(summary: dict[str, Any]) -> list[str]:
    """Rule, primary ML and their hybrid: the three series of the headline comparison."""
    available = list(summary["detectors"])
    primary = summary.get("primary_ml")
    wanted = ["rule", primary, f"hybrid_{primary}"] if primary else ["rule"]
    chosen = [d for d in wanted if d in available]
    return chosen or available[:3]


# -- Navigator -----------------------------------------------------------------------


def _layer(name: str, description: str, techniques: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": name,
        "versions": {"navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description,
        "techniques": techniques,
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "hideDisabled": False,
    }


def _with_parents(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add parent entries so sub-technique cells are expanded in the Navigator."""
    present = {e["techniqueID"] for e in entries}
    parents = {e["techniqueID"].split(".")[0] for e in entries if "." in e["techniqueID"]}
    extra = [{"techniqueID": p, "showSubtechniques": True} for p in sorted(parents - present)]
    for entry in entries:
        if entry["techniqueID"] in parents:
            entry["showSubtechniques"] = True
    return entries + extra


def navigator_layers(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """One coverage layer per detector plus a rule-vs-ML diff layer."""
    summary, techniques = data["summary"], data["techniques"]
    prefix = "[SYNTHETIC] " if summary.get("synthetic") else ""
    layers: dict[str, dict[str, Any]] = {}
    for detector in summary["detectors"]:
        entries: list[dict[str, Any]] = []
        for row in techniques.itertuples(index=False):
            n, seen = int(row.n_runs), int(row.n_runs_with_telemetry)
            if seen == 0:
                entries.append(
                    {"techniqueID": row.technique_id, "color": GAP_COLORS["no_telemetry"],
                     "comment": f"no telemetry in {n} run(s)"}
                )  # fmt: skip
                continue
            rate = float(getattr(row, f"{detector}_rate"))
            entries.append(
                {"techniqueID": row.technique_id, "score": round(100 * rate),
                 "comment": f"detected in {rate:.0%} of {seen} run(s) with telemetry"}
            )  # fmt: skip
        layer = _layer(
            f"{prefix}GapHunter - {detector_name(detector)}",
            "Share of runs in which the technique was detected (0-100).",
            _with_parents(entries),
        )
        layer["gradient"] = {
            "colors": [SEQUENTIAL[0], SEQUENTIAL[-1]],
            "minValue": 0,
            "maxValue": 100,
        }
        layer["legendItems"] = [
            {"label": GAP_LABELS["no_telemetry"], "color": GAP_COLORS["no_telemetry"]}
        ]
        layers[f"layer_{detector}.json"] = layer
    if "gap_category" in techniques:
        entries = [
            {"techniqueID": row.technique_id, "color": GAP_COLORS[row.gap_category],
             "comment": GAP_LABELS[row.gap_category]}
            for row in techniques.itertuples(index=False)
        ]  # fmt: skip
        diff = _layer(
            f"{prefix}GapHunter - rules vs. {detector_name(str(summary['primary_ml']))}",
            "Which detector caught each technique.",
            _with_parents(entries),
        )
        diff["legendItems"] = [{"label": GAP_LABELS[k], "color": c} for k, c in GAP_COLORS.items()]
        layers["layer_diff.json"] = diff
    return layers


# -- figures -------------------------------------------------------------------------


def _pyplot() -> Any:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": [
                "Times New Roman",
                "Times",
                "Nimbus Roman",
                "TeX Gyre Termes",
                "DejaVu Serif",
            ],
            "mathtext.fontset": "stix",
            "font.size": 8,
            "axes.labelsize": 8,
            "axes.titlesize": 8,
            "xtick.labelsize": 7,
            "ytick.labelsize": 7,
            "legend.fontsize": 7,
            "axes.linewidth": 0.6,
            "axes.edgecolor": AXIS,
            "axes.labelcolor": INK,
            "text.color": INK,
            "xtick.color": INK_SECONDARY,
            "ytick.color": INK_SECONDARY,
            "xtick.major.width": 0.6,
            "ytick.major.width": 0.6,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": False,
            "grid.color": GRID,
            "grid.linewidth": 0.5,
            "lines.linewidth": 1.3,
            "hatch.linewidth": 0.5,
            "legend.frameon": False,
            "pdf.fonttype": 42,  # embed TrueType, as IEEE PDF eXpress requires
            "ps.fonttype": 42,
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.02,
        }
    )
    return plt


def _finish(fig: Any, path: Path, synthetic: bool) -> None:
    if synthetic:
        fig.text(0.5, -0.01, SYNTHETIC_NOTE, ha="center", va="top", fontsize=6, color="#e34948")
    fig.savefig(path)
    import matplotlib.pyplot as plt

    plt.close(fig)


def fig_tactic_coverage(data: dict[str, Any], path: Path) -> bool:
    tactics = data["tactics"]
    series = headline_detectors(data["summary"])
    tactics = tactics[tactics["detector"].isin(series)]
    if tactics.empty:
        return False
    plt = _pyplot()
    order = [t for t in TACTIC_ORDER if t in set(tactics["tactic"])]
    fig, ax = plt.subplots(figsize=(COLUMN_WIDTH_IN, 2.1))
    group, gap = 0.78, 0.02
    width = group / len(series)
    x = np.arange(len(order))
    for i, detector in enumerate(series):
        key = detector_key(detector)
        part = tactics[tactics["detector"] == detector].set_index("tactic")["coverage"]
        heights = [100 * float(part.get(t, 0.0)) for t in order]
        ax.bar(
            x - group / 2 + (i + 0.5) * width, heights, width - gap,
            color=DETECTOR_COLORS[key], hatch=DETECTOR_HATCH[key], edgecolor="white",
            linewidth=0.4, label=detector_name(detector), zorder=2,
        )  # fmt: skip
    counts = tactics.drop_duplicates("tactic").set_index("tactic")["n_techniques"]
    ax.set_xticks(x)
    ax.set_xticklabels(
        [f"{tactic_label(t)}\n(n={int(counts[t])})" for t in order],
        rotation=30 if len(order) > 3 else 0,
        ha="right" if len(order) > 3 else "center",
    )
    ax.set_ylim(0, 100)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_ylabel("Techniques detected (%)")
    ax.yaxis.grid(True, zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(axis="x", length=0)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=len(series), handlelength=1.4,
              columnspacing=1.0, borderaxespad=0.2)  # fmt: skip
    _finish(fig, path, bool(data["summary"].get("synthetic")))
    return True


def _curve_figure(data: dict[str, Any], path: Path, kind: str) -> bool:
    curves = {d: c for d, c in data["curves"].items() if not d.startswith("hybrid_")}
    if not curves:
        return False
    plt = _pyplot()
    fig, ax = plt.subplots(figsize=(COLUMN_WIDTH_IN, 2.6))
    for detector, points in curves.items():
        key = detector_key(detector)
        xs, ys = (
            (points["fpr"], points["tpr"])
            if kind == "roc"
            else (points["recall"], points["precision"])
        )
        style: dict[str, Any] = {"color": DETECTOR_COLORS[key], "label": detector_name(detector)}
        if detector == "rule":  # a handful of severity levels: show the operating points
            ax.plot(xs, ys, linestyle="-", marker="o", markersize=3.5, **style)
        else:
            ax.plot(xs, ys, linestyle=DETECTOR_DASH[key], **style)
    if kind == "roc":
        ax.plot([0, 1], [0, 1], color=MUTED, linewidth=0.6, linestyle=(0, (2, 2)), zorder=0)
        ax.set_xlabel("False-positive rate (benign test windows)")
        ax.set_ylabel("True-positive rate (malicious windows)")
        ax.legend(loc="lower right")
    else:
        ax.set_xlabel("Recall (malicious windows)")
        ax.set_ylabel("Precision")
        ax.legend(loc="lower left")
    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(-0.01, 1.02)
    ax.grid(True)
    ax.set_axisbelow(True)
    _finish(fig, path, bool(data["summary"].get("synthetic")))
    return True


def fig_technique_heatmap(data: dict[str, Any], path: Path) -> bool:
    techniques = data["techniques"]
    summary = data["summary"]
    detectors = [d for d in summary["detectors"] if not d.startswith("hybrid_")]
    primary = summary.get("primary_ml")
    if primary and f"hybrid_{primary}" in summary["detectors"]:
        detectors.append(f"hybrid_{primary}")
    if techniques.empty or not detectors:
        return False
    plt = _pyplot()
    from matplotlib.colors import LinearSegmentedColormap
    from matplotlib.patches import Rectangle

    matrix = techniques[[f"{d}_rate" for d in detectors]].to_numpy(dtype=float)
    n_rows, n_cols = matrix.shape
    fig, ax = plt.subplots(figsize=(COLUMN_WIDTH_IN, 0.55 + 0.15 * n_rows))
    cmap = LinearSegmentedColormap.from_list("gaphunter_blue", SEQUENTIAL)
    image = ax.imshow(np.ma.masked_invalid(matrix), cmap=cmap, vmin=0, vmax=1, aspect="auto")
    for r in range(n_rows):
        for c in range(n_cols):
            value = matrix[r, c]
            if np.isnan(value):  # no telemetry: hatched grey, not a zero
                ax.add_patch(Rectangle((c - 0.5, r - 0.5), 1, 1, facecolor="#f0efec",
                                       edgecolor=AXIS, hatch="////", linewidth=0))  # fmt: skip
            elif n_rows <= 45:
                ax.text(c, r, f"{100 * value:.0f}", ha="center", va="center", fontsize=6,
                        color="white" if value > 0.55 else INK)  # fmt: skip
    ax.set_xticks(np.arange(n_cols))
    ax.set_xticklabels([detector_short(d) for d in detectors])
    ax.xaxis.tick_top()
    ax.set_yticks(np.arange(n_rows))
    ax.set_yticklabels(techniques["technique_id"])
    ax.set_xticks(np.arange(-0.5, n_cols, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, n_rows, 1), minor=True)
    ax.grid(which="minor", color="white", linewidth=1.0)  # 2 px surface gap between cells
    ax.tick_params(which="both", length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    bar = fig.colorbar(image, ax=ax, fraction=0.045, pad=0.03, ticks=[0, 0.5, 1])
    bar.ax.set_yticklabels(["0", "50", "100"])
    bar.set_label("Runs detected (%)")
    bar.outline.set_visible(False)
    if np.isnan(matrix).any():
        ax.set_xlabel("Hatched: no telemetry", fontsize=6, color=INK_SECONDARY)
    _finish(fig, path, bool(summary.get("synthetic")))
    return True


# -- LaTeX ---------------------------------------------------------------------------

_TEX_ESCAPES = {"&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_", "{": r"\{", "}": r"\}"}


def tex_escape(text: str) -> str:
    return "".join(_TEX_ESCAPES.get(ch, ch) for ch in str(text))


def _num(value: float, digits: int = 3) -> str:
    return "--" if value != value else f"{value:.{digits}f}"


def _mean_std(row: pd.Series, key: str, multi_seed: bool) -> str:
    mean, std = float(row[key]), float(row[f"{key}_std"])
    if mean != mean:
        return "--"
    return f"{mean:.3f}$\\pm${std:.3f}" if multi_seed and std == std else f"{mean:.3f}"


def _table(columns: str, header: list[str], rows: list[list[str]], caption: str, label: str,
           synthetic: bool, star: bool = False) -> str:  # fmt: skip
    env = "table*" if star else "table"
    note = f" \\textbf{{{tex_escape(SYNTHETIC_NOTE)}.}}" if synthetic else ""
    lines = [
        "% Requires \\usepackage{booktabs}",
        f"\\begin{{{env}}}[t]",
        "\\centering",
        f"\\caption{{{caption}{note}}}",
        f"\\label{{{label}}}",
        f"\\begin{{tabular}}{{{columns}}}",
        "\\toprule",
        " & ".join(header) + " \\\\",
        "\\midrule",
        *[" & ".join(r) + " \\\\" for r in rows],
        "\\bottomrule",
        "\\end{tabular}",
        f"\\end{{{env}}}",
        "",
    ]
    return "\n".join(lines)


def latex_tables(data: dict[str, Any]) -> dict[str, str]:
    summary = data["summary"]
    synthetic = bool(summary.get("synthetic"))
    fpr_pct = f"{100 * float(summary['target_fpr']):g}"
    tables: dict[str, str] = {}

    rows = []
    for _, row in data["detectors"].iterrows():
        multi = int(row["n_seeds"]) > 1
        rows.append([
            tex_escape(detector_name(str(row["detector"]))),
            _mean_std(row, "precision", multi), _mean_std(row, "recall", multi),
            _mean_std(row, "f1", multi), _mean_std(row, "fpr", multi),
            _mean_std(row, "roc_auc", multi), _mean_std(row, "pr_auc", multi),
            f"{int(row['techniques_detected'])}/{int(row['techniques_with_telemetry'])}",
            _num(float(row["median_latency_s"]), 1),
        ])  # fmt: skip
    tables["tab_detectors.tex"] = _table(
        "lrrrrrrrr",
        ["Detector", "Prec.", "Recall", "F1", "FPR", "ROC-AUC", "PR-AUC", "Techn.", "Lat. (s)"],
        rows,
        f"Window-level detection performance (ML thresholds set at {fpr_pct}\\% FPR on benign "
        "validation windows; mean$\\pm$std over seeds) and technique coverage.",
        "tab:detectors", synthetic, star=True,
    )  # fmt: skip

    series = headline_detectors(summary)
    tactics = data["tactics"]
    if not tactics.empty:
        rows = []
        for tactic in [t for t in TACTIC_ORDER if t in set(tactics["tactic"])]:
            part = tactics[tactics["tactic"] == tactic].set_index("detector")
            cells = [
                f"{100 * float(part.at[d, 'coverage']):.0f}\\%" if d in part.index else "--"
                for d in series
            ]
            rows.append(
                [tex_escape(tactic_label(tactic)), str(int(part["n_techniques"].iloc[0])), *cells]
            )
        tables["tab_tactics.tex"] = _table(
            "lr" + "r" * len(series),
            ["Tactic", "\\#Techn.", *[tex_escape(detector_name(d)) for d in series]],
            rows,
            "Share of techniques detected per ATT\\&CK tactic.",
            "tab:tactics", synthetic,
        )  # fmt: skip

    techniques = data["techniques"]
    rows = []
    for _, row in techniques.iterrows():
        seen = int(row["n_runs_with_telemetry"])
        cells = ["--" if seen == 0 else f"{100 * float(row[f'{d}_rate']):.0f}\\%" for d in series]
        gap = GAP_LABELS.get(str(row.get("gap_category", "")), "")
        rows.append(
            [
                tex_escape(row["technique_id"]),
                tex_escape(str(row["name"])[:38]),
                *cells,
                tex_escape(gap),
            ]
        )
    tables["tab_techniques.tex"] = _table(
        "ll" + "r" * len(series) + "l",
        ["ID", "Technique", *[tex_escape(detector_name(d)) for d in series], "Outcome"],
        rows,
        "Share of runs detected per technique.",
        "tab:techniques", synthetic, star=True,
    )  # fmt: skip
    return tables


# -- entry point ---------------------------------------------------------------------


def summary_markdown(data: dict[str, Any], written: list[str]) -> str:
    summary = data["summary"]
    lines = ["# GapHunter report", ""]
    if summary.get("synthetic"):
        lines += [f"**{SYNTHETIC_NOTE}.** Generated by `gaphunter demo`.", ""]
    lines += [
        f"- Techniques: {summary['n_techniques']} ({summary['n_attack_runs']} runs, "
        f"{summary['n_runs_without_telemetry']} without telemetry)",
        f"- Windows: {summary['window_s']:g} s; benign split: {summary['split_sizes']}",
        f"- ML threshold: {100 * float(summary['target_fpr']):g}% FPR on benign validation windows",
        f"- Rule threshold: alert level >= {summary['rule_min_level']}",
    ]
    if "gap_counts" in summary:
        counts = ", ".join(f"{GAP_LABELS[k]}: {v}" for k, v in summary["gap_counts"].items())
        lines.append(f"- Outcome per technique: {counts}")
    lines += [
        "",
        "| Detector | Precision | Recall | F1 | FPR | Techniques |",
        "|---|---|---|---|---|---|",
    ]
    for _, row in data["detectors"].iterrows():
        cells = [_num(float(row[k])) for k in ("precision", "recall", "f1", "fpr")]
        covered = f"{int(row['techniques_detected'])}/{int(row['techniques_with_telemetry'])}"
        lines.append(f"| {detector_name(str(row['detector']))} | {' | '.join(cells)} | {covered} |")
    lines += ["", "## Files", "", *[f"- `{name}`" for name in written], ""]
    return "\n".join(lines)


def build_report(run: RunDir, output: Path) -> list[str]:
    """Write layers, figures, tables and CSVs to ``output``. Returns the file names."""
    data = load_eval(run)
    output.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    for name, layer in navigator_layers(data).items():
        (output / name).write_text(json.dumps(layer, indent=2), encoding="utf-8")
        written.append(name)

    figures: dict[str, Callable[[Path], bool]] = {
        "fig_tactic_coverage.pdf": lambda p: fig_tactic_coverage(data, p),
        "fig_roc.pdf": lambda p: _curve_figure(data, p, "roc"),
        "fig_pr.pdf": lambda p: _curve_figure(data, p, "pr"),
        "fig_technique_heatmap.pdf": lambda p: fig_technique_heatmap(data, p),
    }
    for name, draw in figures.items():
        if draw(output / name):
            written.append(name)
        else:
            log.warning("report.figure_skipped", figure=name, reason="no data")

    for name, text in latex_tables(data).items():
        (output / name).write_text(text, encoding="utf-8")
        written.append(name)

    for csv_name in ("detector_metrics.csv", "technique_detection.csv", "tactic_coverage.csv",
                     "execution_detection.csv"):  # fmt: skip
        source = run.eval_dir / csv_name
        if source.is_file():
            shutil.copyfile(source, output / csv_name)
            written.append(csv_name)
    shutil.copyfile(run.manifest_path, output / "manifest.json")
    written.append("manifest.json")
    (output / "report.md").write_text(summary_markdown(data, written), encoding="utf-8")
    written.append("report.md")
    log.info("report.done", output=str(output), files=len(written))
    return written
