"""Evaluation: window-level metrics, technique/tactic coverage, latency, gap analysis.

Protocol
--------
* Negatives are benign **test** windows of the baseline, never used for fitting or for
  choosing thresholds.
* Thresholds come from benign **validation** windows at the target false-positive rate.
* Leave-technique-out: when a detector has several hyper-parameter entries, the entry
  used for technique *t* is the one with the best average precision on validation
  negatives plus the malicious windows of every technique **except** *t*. Nothing about
  *t* influences how *t* is scored.
* A run of a technique is detected when at least one of its malicious windows is flagged.
  A technique is detected when at least ``evaluation.technique_min_rate`` of its runs are.
* Runs with no malicious window (nothing of the activity reached the logs) are reported
  as ``no_telemetry`` and left out of detection rates: no log-based detector can see them.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

from gaphunter.attack import TACTIC_ORDER, describe, load_techniques
from gaphunter.config import Config
from gaphunter.detectors.rule import LEVELS, rule_window_scores
from gaphunter.errors import GapHunterError
from gaphunter.log import get_logger
from gaphunter.rundir import RunDir
from gaphunter.schema import WINDOW_META_COLUMNS

log = get_logger(__name__)

BoolArray = np.ndarray[Any, np.dtype[np.bool_]]
FloatArray = np.ndarray[Any, np.dtype[np.float64]]
IntArray = np.ndarray[Any, np.dtype[np.intp]]


@dataclass
class Frame:
    """Index arrays over the windows table that every detector is evaluated on."""

    windows: pd.DataFrame
    val: IntArray
    test: IntArray
    positives: dict[str, IntArray]  # technique -> malicious windows
    in_session_benign: dict[str, IntArray]  # technique -> benign windows of its sessions
    executions: pd.DataFrame  # attack sessions: execution_id, technique_id
    techniques: list[str]


@dataclass
class Decision:
    """What one detector (for one seed) decided, per held-out technique."""

    detector: str
    seed: int
    pred_pos: dict[str, BoolArray] = field(default_factory=dict)
    pred_test: dict[str, BoolArray] = field(default_factory=dict)
    pred_in_session: dict[str, BoolArray] = field(default_factory=dict)
    score_pos: dict[str, FloatArray] = field(default_factory=dict)
    score_test: dict[str, FloatArray] = field(default_factory=dict)
    config: dict[str, str] = field(default_factory=dict)
    threshold: dict[str, float] = field(default_factory=dict)


def build_frame(run: RunDir) -> Frame:
    for path, hint in ((run.windows_path, "features"), (run.splits_path, "train")):
        if not path.is_file():
            raise GapHunterError(f"{path.name} not found; run 'gaphunter {hint}' first")
    windows = pd.read_parquet(run.windows_path, columns=list(WINDOW_META_COLUMNS))
    windows = windows.merge(pd.read_parquet(run.splits_path), on="window_id", how="left")
    windows = windows.reset_index(drop=True)
    split = windows["split"].to_numpy()
    val = np.flatnonzero(split == "val")
    test = np.flatnonzero(split == "test")
    if len(val) == 0 or len(test) == 0:
        raise GapHunterError("benign validation/test windows are missing; collect more baseline")

    sessions = [s for s in run.collected() if s.kind == "attack" and s.technique_id]
    executions = pd.DataFrame(
        {
            "execution_id": [s.execution_id for s in sessions],
            "technique_id": [str(s.technique_id) for s in sessions],
        }
    )
    techniques = sorted(set(executions["technique_id"]))
    exec_technique = dict(zip(executions["execution_id"], executions["technique_id"], strict=True))
    session_technique = windows["execution_id"].map(exec_technique)
    label = windows["label"].to_numpy(dtype=bool)
    positives: dict[str, IntArray] = {}
    in_session: dict[str, IntArray] = {}
    for technique in techniques:
        mine = (session_technique == technique).to_numpy()
        positives[technique] = np.flatnonzero(mine & label)
        in_session[technique] = np.flatnonzero(mine & ~label)
    return Frame(windows, val, test, positives, in_session, executions, techniques)


def _average_precision(pos: FloatArray, neg: FloatArray) -> float:
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    y = np.r_[np.ones(len(pos)), np.zeros(len(neg))]
    return float(average_precision_score(y, np.r_[pos, neg]))


def _roc_auc(pos: FloatArray, neg: FloatArray) -> float:
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    y = np.r_[np.ones(len(pos)), np.zeros(len(neg))]
    return float(roc_auc_score(y, np.r_[pos, neg]))


def decide_ml(
    frame: Frame, scores: pd.DataFrame, detector: str, seed: int, target_fpr: float
) -> Decision:
    """Thresholds from validation, hyper-parameters leave-technique-out."""
    subset = scores[(scores["detector"] == detector) & (scores["seed"] == seed)]
    order = frame.windows["window_id"]
    by_config: dict[str, FloatArray] = {}
    for config_id, part in subset.groupby("config_id", sort=True):
        aligned = part.set_index("window_id")["score"].reindex(order)
        if aligned.isna().any():
            raise GapHunterError(f"scores for {config_id} do not cover every window; retrain")
        by_config[str(config_id)] = aligned.to_numpy(dtype=np.float64)
    if not by_config:
        raise GapHunterError(f"no scores for detector {detector!r} seed {seed}; run 'train'")
    thresholds = {
        c: float(np.quantile(s[frame.val], 1.0 - target_fpr, method="higher"))
        for c, s in by_config.items()
    }
    decision = Decision(detector, seed)
    configs = list(by_config)
    for technique in frame.techniques:
        chosen = configs[0]
        if len(configs) > 1:
            others = [frame.positives[t] for t in frame.techniques if t != technique]
            other_idx = np.concatenate(others) if others else np.array([], dtype=np.intp)
            if len(other_idx):
                quality = {
                    c: _average_precision(s[other_idx], s[frame.val]) for c, s in by_config.items()
                }
                chosen = max(configs, key=lambda c: (quality[c], -configs.index(c)))
        s, tau = by_config[chosen], thresholds[chosen]
        decision.config[technique] = chosen
        decision.threshold[technique] = tau
        decision.score_pos[technique] = s[frame.positives[technique]]
        decision.score_test[technique] = s[frame.test]
        decision.pred_pos[technique] = s[frame.positives[technique]] > tau
        decision.pred_test[technique] = s[frame.test] > tau
        decision.pred_in_session[technique] = s[frame.in_session_benign[technique]] > tau
    return decision


def decide_rule(frame: Frame, rule_scores: pd.DataFrame, min_level: str) -> Decision:
    aligned = rule_scores.set_index("window_id")["score"].reindex(frame.windows["window_id"])
    s = aligned.fillna(0.0).to_numpy(dtype=np.float64)
    level = float(LEVELS[min_level])
    decision = Decision("rule", 0)
    for technique in frame.techniques:
        decision.config[technique] = f"rule>={min_level}"
        decision.threshold[technique] = level
        decision.score_pos[technique] = s[frame.positives[technique]]
        decision.score_test[technique] = s[frame.test]
        decision.pred_pos[technique] = s[frame.positives[technique]] >= level
        decision.pred_test[technique] = s[frame.test] >= level
        decision.pred_in_session[technique] = s[frame.in_session_benign[technique]] >= level
    return decision


def decide_hybrid(rule: Decision, ml: Decision) -> Decision:
    """Rule OR ML. A set of alerts has no single score, so no ROC/PR for the hybrid."""
    decision = Decision(f"hybrid_{ml.detector}", ml.seed)
    for technique in ml.pred_pos:
        decision.config[technique] = f"{rule.config[technique]} OR {ml.config[technique]}"
        decision.pred_pos[technique] = rule.pred_pos[technique] | ml.pred_pos[technique]
        decision.pred_test[technique] = rule.pred_test[technique] | ml.pred_test[technique]
        decision.pred_in_session[technique] = (
            rule.pred_in_session[technique] | ml.pred_in_session[technique]
        )
    return decision


def execution_table(frame: Frame, decision: Decision) -> pd.DataFrame:
    """One row per attack session: detected?, latency, number of malicious windows."""
    windows = frame.windows
    rows: list[dict[str, Any]] = []
    for execution_id, technique in zip(
        frame.executions["execution_id"], frame.executions["technique_id"], strict=True
    ):
        idx = frame.positives[technique]
        mine = windows["execution_id"].to_numpy()[idx] == execution_id
        own_idx, own_pred = idx[mine], decision.pred_pos[technique][mine]
        detected = bool(own_pred.any()) if len(own_idx) else False
        latency = float("nan")
        if detected:
            first = windows["first_malicious_ts"].to_numpy()[own_idx].min()
            flagged_end = windows["window_end"].to_numpy()[own_idx[own_pred]].min()
            latency = max(0.0, float((flagged_end - first) / np.timedelta64(1, "s")))
        rows.append(
            {
                "execution_id": execution_id,
                "technique_id": technique,
                "detector": decision.detector,
                "seed": decision.seed,
                "config": decision.config[technique],
                "n_malicious_windows": int(len(own_idx)),
                "has_telemetry": bool(len(own_idx)),
                "detected": detected,
                "latency_s": latency,
            }
        )
    return pd.DataFrame(rows)


def window_metrics(frame: Frame, decision: Decision) -> dict[str, float]:
    tp = sum(int(decision.pred_pos[t].sum()) for t in frame.techniques)
    n_pos = sum(len(frame.positives[t]) for t in frame.techniques)
    fprs = [float(decision.pred_test[t].mean()) for t in frame.techniques]
    fpr = float(np.mean(fprs)) if fprs else float("nan")
    fp = fpr * len(frame.test)  # expected false positives on the benign test set
    recall = tp / n_pos if n_pos else float("nan")
    precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision == precision and recall == recall and (precision + recall) > 0
        else float("nan")
    )
    in_session = np.concatenate(
        [decision.pred_in_session[t] for t in frame.techniques] or [np.array([], dtype=bool)]
    )
    metrics = {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "roc_auc": float("nan"),
        "pr_auc": float("nan"),
        "in_session_benign_rate": float(in_session.mean()) if len(in_session) else float("nan"),
        "n_malicious_windows": float(n_pos),
        "n_benign_test_windows": float(len(frame.test)),
    }
    if decision.score_pos:
        rocs = [_roc_auc(decision.score_pos[t], decision.score_test[t]) for t in frame.techniques]
        prs = [
            _average_precision(decision.score_pos[t], decision.score_test[t])
            for t in frame.techniques
        ]
        if any(v == v for v in rocs):
            metrics["roc_auc"] = float(np.nanmean(rocs))
            metrics["pr_auc"] = float(np.nanmean(prs))
    return metrics


def _curves(decision: Decision, frame: Frame) -> dict[str, Any] | None:
    """Pooled ROC and PR points for plotting (most frequently selected configuration)."""
    if not decision.score_pos or not frame.techniques:
        return None
    modal = Counter(decision.config.values()).most_common(1)[0][0]
    members = [t for t in frame.techniques if decision.config[t] == modal]
    pos = np.concatenate([decision.score_pos[t] for t in members])
    neg = decision.score_test[members[0]]
    if len(pos) == 0 or len(neg) == 0:
        return None
    y = np.r_[np.ones(len(pos)), np.zeros(len(neg))]
    s = np.r_[pos, neg]
    fpr, tpr, _ = roc_curve(y, s)
    precision, recall, _ = precision_recall_curve(y, s)

    def thin(values: np.ndarray[Any, Any]) -> list[float]:
        step = max(1, len(values) // 300)
        kept = values[::step]
        if len(values) and kept[-1] != values[-1]:
            kept = np.r_[kept, values[-1]]
        return [float(v) for v in kept]

    return {
        "fpr": thin(fpr),
        "tpr": thin(tpr),
        "recall": thin(recall),
        "precision": thin(precision),
        "config": modal,
    }


def _mean_std(values: list[float]) -> tuple[float, float]:
    clean = [v for v in values if v == v]
    if not clean:
        return float("nan"), float("nan")
    return float(np.mean(clean)), float(np.std(clean))


def evaluate(run: RunDir, config: Config) -> dict[str, Any]:
    """Run the full evaluation and write CSV/JSON files into ``<run>/eval``."""
    frame = build_frame(run)
    if not frame.techniques:
        raise GapHunterError("no collected attack sessions to evaluate")
    known = load_techniques(config.evaluation.techniques_file)

    decisions: list[Decision] = []
    rule: Decision | None = None
    if run.alerts_path.is_file():
        feature_cols = ["window_id", "execution_id", "window_start", "window_end", "technique_id"]
        rule_scores = rule_window_scores(
            run,
            frame.windows[feature_cols],
            pd.read_parquet(run.alerts_path),
            exclude_root=config.features.exclude_root_process,
        )
        rule_scores.to_parquet(run.eval_dir.parent / "rule_scores.parquet", index=False)
        rule = decide_rule(frame, rule_scores, config.rules.min_level)
        decisions.append(rule)
    else:
        log.warning("evaluate.no_rule_alerts", hint="run 'gaphunter rules' to include Hayabusa")

    if run.scores_path.is_file():
        scores = pd.read_parquet(run.scores_path)
        for detector in sorted(scores["detector"].unique()):
            for seed in sorted(int(s) for s in scores["seed"].unique()):
                ml = decide_ml(frame, scores, detector, seed, config.ml.target_fpr)
                decisions.append(ml)
                if rule is not None:
                    decisions.append(decide_hybrid(rule, ml))
    else:
        log.warning("evaluate.no_ml_scores", hint="run 'gaphunter train' to include ML")
    if not decisions:
        raise GapHunterError("nothing to evaluate: neither rule alerts nor ML scores exist")

    run.eval_dir.mkdir(exist_ok=True)
    executions = pd.concat([execution_table(frame, d) for d in decisions], ignore_index=True)
    detectors = list(dict.fromkeys(d.detector for d in decisions))

    # -- per technique ---------------------------------------------------------------
    with_telemetry = executions[executions["has_telemetry"]]
    rate = (
        with_telemetry.groupby(["technique_id", "detector"])["detected"].mean().unstack("detector")
    )
    per_run = executions[executions["detector"] == detectors[0]]
    per_run = per_run[per_run["seed"] == per_run["seed"].min()]
    technique_rows: list[dict[str, Any]] = []
    for technique in frame.techniques:
        meta = describe(technique, known)
        runs = per_run[per_run["technique_id"] == technique]
        row: dict[str, Any] = {
            "technique_id": technique,
            "name": meta.name,
            "tactics": ";".join(meta.tactics),
            "n_runs": int(len(runs)),
            "n_runs_with_telemetry": int(runs["has_telemetry"].sum()),
        }
        for detector in detectors:
            known_cell = technique in rate.index and detector in rate.columns
            value = rate.at[technique, detector] if known_cell else float("nan")
            row[f"{detector}_rate"] = float(value)
            row[f"{detector}_detected"] = bool(
                value == value and value >= config.evaluation.technique_min_rate
            )
        technique_rows.append(row)
    techniques = pd.DataFrame(technique_rows)

    primary_ml = config.ml.hybrid_ml if config.ml.hybrid_ml in detectors else None
    if rule is not None and primary_ml is not None:

        def gap(row: pd.Series) -> str:
            if row["n_runs_with_telemetry"] == 0:
                return "no_telemetry"
            by_rule, by_ml = bool(row["rule_detected"]), bool(row[f"{primary_ml}_detected"])
            if by_rule and by_ml:
                return "both"
            if by_rule:
                return "rule_only"
            return "ml_only" if by_ml else "neither"

        techniques["gap_category"] = techniques.apply(gap, axis=1)

    # -- per tactic ------------------------------------------------------------------
    tactic_rows: list[dict[str, Any]] = []
    visible = techniques[techniques["n_runs_with_telemetry"] > 0]
    for tactic in TACTIC_ORDER:
        members = visible[visible["tactics"].str.split(";").apply(lambda ts, t=tactic: t in ts)]
        if members.empty:
            continue
        for detector in detectors:
            hit = int(members[f"{detector}_detected"].sum())
            tactic_rows.append(
                {
                    "tactic": tactic,
                    "detector": detector,
                    "n_techniques": int(len(members)),
                    "n_detected": hit,
                    "coverage": hit / len(members),
                }
            )
    tactics = pd.DataFrame(tactic_rows)

    # -- per detector ----------------------------------------------------------------
    detector_rows: list[dict[str, Any]] = []
    for detector in detectors:
        per_seed = [window_metrics(frame, d) for d in decisions if d.detector == detector]
        row = {"detector": detector, "n_seeds": len(per_seed)}
        for key in (
            "precision",
            "recall",
            "f1",
            "fpr",
            "roc_auc",
            "pr_auc",
            "in_session_benign_rate",
        ):
            mean, std = _mean_std([m[key] for m in per_seed])
            row[key], row[f"{key}_std"] = mean, std
        mine = with_telemetry[with_telemetry["detector"] == detector]
        row["run_detection_rate"] = float(mine["detected"].mean()) if len(mine) else float("nan")
        latencies = mine.loc[mine["detected"], "latency_s"]
        row["median_latency_s"] = float(latencies.median()) if len(latencies) else float("nan")
        n_visible = int((techniques["n_runs_with_telemetry"] > 0).sum())
        n_hit = int(visible[f"{detector}_detected"].sum())
        row["techniques_detected"] = n_hit
        row["techniques_with_telemetry"] = n_visible
        row["technique_coverage"] = n_hit / n_visible if n_visible else float("nan")
        detector_rows.append(row)
    detector_metrics = pd.DataFrame(detector_rows)

    curves: dict[str, Any] = {}
    for detector in detectors:
        first = next(d for d in decisions if d.detector == detector)
        points = _curves(first, frame)
        if points is not None:
            curves[detector] = points

    split_sizes = frame.windows["split"].value_counts().to_dict()
    summary: dict[str, Any] = {
        "synthetic": run.is_synthetic(),
        "target_fpr": config.ml.target_fpr,
        "rule_min_level": config.rules.min_level,
        "technique_min_rate": config.evaluation.technique_min_rate,
        "window_s": config.features.window_s,
        "seeds": sorted({d.seed for d in decisions if d.detector != "rule"}),
        "primary_ml": primary_ml,
        "detectors": detectors,
        "split_sizes": {str(k): int(v) for k, v in split_sizes.items()},
        "n_techniques": len(frame.techniques),
        "n_attack_runs": int(len(frame.executions)),
        "n_runs_without_telemetry": int((~per_run["has_telemetry"]).sum()),
        "selected_configs": {
            f"{d.detector}@{d.seed}": d.config for d in decisions if d.detector != "rule"
        },
    }
    if "gap_category" in techniques:
        summary["gap_counts"] = {
            str(k): int(v) for k, v in techniques["gap_category"].value_counts().items()
        }

    detector_metrics.to_csv(run.eval_dir / "detector_metrics.csv", index=False)
    techniques.to_csv(run.eval_dir / "technique_detection.csv", index=False)
    tactics.to_csv(run.eval_dir / "tactic_coverage.csv", index=False)
    executions.to_csv(run.eval_dir / "execution_detection.csv", index=False)
    (run.eval_dir / "curves.json").write_text(json.dumps(curves), encoding="utf-8")
    (run.eval_dir / "metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    log.info("evaluate.done", detectors=detectors, techniques=len(frame.techniques))
    return {
        "summary": summary,
        "detector_metrics": detector_metrics,
        "techniques": techniques,
        "tactics": tactics,
        "executions": executions,
        "curves": curves,
    }
