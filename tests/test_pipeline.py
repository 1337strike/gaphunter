"""End-to-end on synthetic data: label -> features -> rules -> train -> evaluate -> report."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from gaphunter.config import Config
from gaphunter.detectors import run_rules, train
from gaphunter.detectors.ml import AeSettings, NumpyAutoencoder, Preprocessor, split_windows
from gaphunter.detectors.rule import normalize_alert, technique_matches
from gaphunter.evaluation import build_frame, decide_ml, evaluate
from gaphunter.features import build_windows
from gaphunter.labeler import label_run
from gaphunter.reporter import build_report
from gaphunter.rundir import RunDir
from gaphunter.synth import make_demo_run

REPO = Path(__file__).parents[1]


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> tuple[RunDir, Config]:
    cfg = Config.model_validate(
        {
            "results_dir": str(tmp_path_factory.mktemp("results")),
            "ml": {"seeds": [1, 2], "ae_epochs": 60, "ae_backend": "numpy"},
            "evaluation": {"techniques_file": str(REPO / "configs" / "techniques.yaml")},
        }
    )
    run = make_demo_run(cfg, n_baseline=10, slice_seconds=450)
    label_run(run, cfg.labeler)
    build_windows(run, cfg.features)
    run_rules(run, cfg.rules)  # fabricated alert files already exist: Hayabusa is not run
    train(run, cfg.ml, cfg.seed)
    return run, cfg


def test_manifest_marks_synthetic(demo: tuple[RunDir, Config]) -> None:
    assert demo[0].is_synthetic()


def test_split_keeps_sessions_whole(demo: tuple[RunDir, Config]) -> None:
    run, cfg = demo
    windows = pd.read_parquet(run.windows_path)
    merged = windows.merge(split_windows(windows, cfg.ml, cfg.seed), on="window_id")
    assert (merged.groupby("execution_id")["split"].nunique() == 1).all()
    assert set(merged.loc[merged["source"] == "attack", "split"]) == {"attack"}
    assert {"train", "val", "test"} <= set(merged["split"])


def test_every_gap_category_is_found(demo: tuple[RunDir, Config]) -> None:
    run, cfg = demo
    result = evaluate(run, cfg)
    gaps = result["techniques"].set_index("technique_id")["gap_category"].to_dict()
    assert gaps == {
        "T1082": "both",
        "T1057": "rule_only",
        "T1033": "ml_only",
        "T1016": "neither",
        "T1083": "no_telemetry",
    }
    metrics = result["detector_metrics"].set_index("detector")
    assert metrics.at["rule", "techniques_detected"] == 2
    assert metrics.at["hybrid_autoencoder", "techniques_detected"] == 3
    assert metrics.at["autoencoder", "fpr"] <= 0.05
    assert 0 < metrics.at["rule", "fpr"] < 0.1  # the planted benign rule hit
    assert np.isnan(metrics.at["hybrid_autoencoder", "roc_auc"])
    assert metrics.at["autoencoder", "roc_auc"] > 0.6
    tactics = result["tactics"]
    hybrid = tactics[tactics["detector"] == "hybrid_autoencoder"].iloc[0]
    assert hybrid["tactic"] == "discovery" and hybrid["n_techniques"] == 4
    assert hybrid["coverage"] == pytest.approx(0.75)
    detected = result["executions"].query("detected")
    assert (detected["latency_s"] >= 0).all()


def test_thresholds_respect_target_fpr_on_validation(demo: tuple[RunDir, Config]) -> None:
    run, cfg = demo
    frame = build_frame(run)
    scores = pd.read_parquet(run.scores_path)
    decision = decide_ml(frame, scores, "iforest", 1, cfg.ml.target_fpr)
    for technique, config_id in decision.config.items():
        part = scores[(scores["config_id"] == config_id) & (scores["seed"] == 1)]
        aligned = part.set_index("window_id")["score"].reindex(frame.windows["window_id"])
        val_scores = aligned.to_numpy()[frame.val]
        assert (val_scores > decision.threshold[technique]).mean() <= cfg.ml.target_fpr


def test_hyperparameters_are_chosen_without_the_held_out_technique(
    demo: tuple[RunDir, Config],
) -> None:
    run, cfg = demo
    frame = build_frame(run)
    ids = frame.windows["window_id"].to_numpy()
    target = "T1082"
    others = np.concatenate([frame.positives[t] for t in frame.techniques if t != target])
    # config A is perfect on the held-out technique only; config B on all the others
    a = np.zeros(len(ids))
    a[frame.positives[target]] = 10.0
    b = np.zeros(len(ids))
    b[others] = 10.0
    scores = pd.concat(
        [
            pd.DataFrame({"window_id": ids, "detector": "x", "config_id": c, "seed": 0, "score": s})
            for c, s in (("x#0", a), ("x#1", b))
        ]
    )
    decision = decide_ml(frame, scores, "x", 0, 0.01)
    assert decision.config[target] == "x#1"  # A would win only by peeking at the target
    assert not decision.pred_pos[target].any()


def test_report_files(demo: tuple[RunDir, Config], tmp_path: Path) -> None:
    run, cfg = demo
    evaluate(run, cfg)
    written = build_report(run, tmp_path / "report")
    out = tmp_path / "report"
    for name in (
        "layer_rule.json", "layer_autoencoder.json", "layer_diff.json", "fig_roc.pdf",
        "fig_pr.pdf", "fig_tactic_coverage.pdf", "fig_technique_heatmap.pdf",
        "tab_detectors.tex", "tab_tactics.tex", "tab_techniques.tex",
        "technique_detection.csv", "report.md", "manifest.json",
    ):  # fmt: skip
        assert name in written and (out / name).stat().st_size > 0
    assert (out / "fig_roc.pdf").read_bytes().startswith(b"%PDF")
    layer = json.loads((out / "layer_diff.json").read_text())
    assert layer["domain"] == "enterprise-attack" and layer["name"].startswith("[SYNTHETIC]")
    colors = {t["techniqueID"]: t["color"] for t in layer["techniques"]}
    assert colors["T1033"] == "#1baf7a" and colors["T1083"] == "#c3c2b7"
    rule = json.loads((out / "layer_rule.json").read_text())
    scores = {t["techniqueID"]: t.get("score") for t in rule["techniques"]}
    assert scores["T1082"] == 100 and scores["T1016"] == 0 and scores["T1083"] is None
    tex = (out / "tab_detectors.tex").read_text()
    assert "\\toprule" in tex and "\\bottomrule" in tex and "SYNTHETIC" in tex
    assert "SYNTHETIC" in (out / "report.md").read_text()


def test_preprocessor_is_fitted_on_benign_only() -> None:
    columns = ["f_n_events", "f_never_seen", "f_tok_000", "f_tok_001"]
    benign = np.array([[10, 0, 3, 0], [12, 0, 1, 0], [8, 0, 2, 0]], dtype=float)
    prep = Preprocessor(columns).fit(benign)
    z = prep.transform(np.array([[10, 5, 0, 4]], dtype=float))
    assert abs(z[0, 0]) < 1.0  # an ordinary event count
    assert z[0, 1] == pytest.approx(np.log1p(5))  # constant-in-benign column keeps unit scale
    assert z[0, 3] > z[0, 2]  # a token never seen in benign data dominates the TF-IDF part


def test_numpy_autoencoder_scores_outliers_higher() -> None:
    rng = np.random.default_rng(0)
    base = rng.normal(size=(300, 2))
    data = np.hstack([base, base @ np.array([[1.0, 0.5], [0.3, 1.0]])])  # 4-d, rank 2
    model = NumpyAutoencoder(AeSettings(16, 2, 150, 32, 5e-3, 30), seed=0)
    model.fit(data)
    normal = model.score(data).mean()
    outliers = model.score(rng.normal(size=(50, 4)) * 3).mean()
    assert outliers > 5 * normal


def test_torch_autoencoder_if_available() -> None:
    pytest.importorskip("torch")
    from gaphunter.detectors.ml import TorchAutoencoder

    rng = np.random.default_rng(0)
    base = rng.normal(size=(300, 2))
    data = np.hstack([base, base])
    model = TorchAutoencoder(AeSettings(16, 2, 100, 32, 5e-3, 30), seed=0)
    model.fit(data)
    assert model.score(rng.normal(size=(50, 4)) * 3).mean() > 3 * model.score(data).mean()


def test_hayabusa_alert_normalisation() -> None:
    verbose = {
        "Timestamp": "2026-11-14T02:00:05.1234567Z", "RuleTitle": "Proc Exec", "Level": "med",
        "Channel": "Sysmon", "EventID": 1, "RecordID": 42,
        "MitreTactics": ["Exec"], "MitreTags": ["T1059.001", "S0002"],
        "RuleFile": "x.yml", "EvtxFile": "/runs/r/evtx/T1059.001-1-r1/sysmon.evtx",
    }  # fmt: skip
    alert = normalize_alert(verbose, "e")
    assert alert is not None
    assert alert["level"] == "medium" and alert["level_num"] == 3
    assert alert["channel"] == "sysmon" and alert["record_id"] == 42
    assert alert["mitre_tags"] == ["T1059.001"]
    assert alert["ts_utc"].microsecond == 123456
    csv_style = {
        "Timestamp": "2026-11-14 09:00:05.123 +07:00", "Level": "crit", "Channel": "Sec",
        "RecordID": "7", "MitreTags": "T1003 ¦ T1003.001", "RuleTitle": "x",
    }  # fmt: skip
    alert = normalize_alert(csv_style, "e")
    assert alert is not None
    assert alert["level_num"] == 5 and alert["channel"] == "security"
    assert alert["ts_utc"].hour == 2 and alert["mitre_tags"] == ["T1003", "T1003.001"]
    assert normalize_alert({"Level": "high"}, "e") is None


def test_technique_matching_handles_sub_techniques() -> None:
    assert technique_matches(["T1059.001"], "T1059.001")
    assert technique_matches(["T1059"], "T1059.001")
    assert technique_matches(["T1059.001"], "T1059")
    assert not technique_matches(["T1059.003"], "T1059.001")
    assert not technique_matches(["T1082"], None)
