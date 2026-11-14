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


# -- 0.2: rarity, ensemble, deployable bundles, detection, import ---------------------


def test_scores_include_rarity_and_ensemble(demo: tuple[RunDir, Config]) -> None:
    scores = pd.read_parquet(demo[0].scores_path)
    assert {"iforest", "autoencoder", "rarity", "ensemble"} <= set(scores["detector"])
    ensemble = scores[scores["detector"] == "ensemble"]
    assert set(ensemble["config_id"]) == {"ensemble#0"} and ensemble["score"].notna().all()


def test_rarity_detector_scores_unseen_buckets() -> None:
    from gaphunter.detectors.ml import RarityDetector

    columns = ["f_n_events", "f_tok_000", "f_tok_001", "f_img_00", "f_pair_00"]
    benign = np.array([[5, 1, 0, 1, 0]] * 50, dtype=float)
    model = RarityDetector({"top_k": 2}, columns)
    model.fit(benign)
    seen, unseen = model.score(np.array([[500, 3, 0, 1, 0], [5, 1, 2, 1, 4]], dtype=float))
    assert unseen > 10 * max(seen, 1e-9)  # event volume alone does not matter
    assert model.uses_raw


@pytest.fixture(scope="module")
def bundle_path(demo: tuple[RunDir, Config], tmp_path_factory: pytest.TempPathFactory) -> Path:
    from gaphunter.deploy import fit_bundle, save_bundle

    run, cfg = demo
    path = tmp_path_factory.mktemp("models") / "ensemble.joblib"
    save_bundle(fit_bundle(run, cfg, "ensemble"), path)
    return path


def _events(run: RunDir, execution_id: str) -> pd.DataFrame:
    from gaphunter.collector.store import read_events

    frame = read_events(run.labeled_path(execution_id)).to_pandas()
    frame["label"] = False  # detection sees unlabelled logs
    frame["label_reason"] = None
    return frame


def test_bundle_roundtrip_detects_and_explains(
    demo: tuple[RunDir, Config], bundle_path: Path
) -> None:
    from gaphunter.deploy import detect_events, load_bundle, render_alert

    run, cfg = demo
    bundle = load_bundle(bundle_path)
    card = json.loads(Path(str(bundle_path) + ".json").read_text())
    assert card["name"] == "ensemble" and card["synthetic"] is True
    assert [m["detector"] for m in card["members"]] == ["iforest", "autoencoder", "rarity"]

    alerts, summary = detect_events(_events(run, "T1082-1-r1"), bundle, cfg.detect)
    assert summary["windows"] >= 2 and summary["alerts"] == len(alerts) >= 1
    alert = alerts[0]
    assert alert["type"] == "ml" and alert["host"] == "SYNTH-HOST"
    assert alert["score"] > alert["threshold"] and alert["severity"] in {"low", "medium", "high"}
    explanation = alert["explanation"]
    assert explanation["top_features"] and all("what" in f for f in explanation["top_features"])
    assert "synth-tool" in explanation["rarest_commands"][0]["text"]
    assert any(p["image"].startswith("synth-") for p in explanation["programs_started"])
    text = render_alert(alert)
    assert "score" in text and "synth-tool" in text

    quiet, quiet_summary = detect_events(_events(run, "baseline-0010"), bundle, cfg.detect)
    assert len(quiet) <= 1 and quiet_summary["windows"] > 5

    plain, _ = detect_events(_events(run, "T1082-1-r1"), bundle, cfg.detect, explain=False)
    assert "explanation" not in plain[0]


def test_load_bundle_rejects_other_files(tmp_path: Path) -> None:
    import joblib

    from gaphunter.deploy import load_bundle
    from gaphunter.errors import GapHunterError

    with pytest.raises(GapHunterError, match="not found"):
        load_bundle(tmp_path / "missing.joblib")
    other = tmp_path / "other.joblib"
    joblib.dump({"not": "a bundle"}, other)
    with pytest.raises(GapHunterError, match="not a GapHunter model bundle"):
        load_bundle(other)
    garbage = tmp_path / "garbage.joblib"
    garbage.write_bytes(b"nope")
    with pytest.raises(GapHunterError, match="cannot load"):
        load_bundle(garbage)


def test_import_baseline_and_group_rule_alerts(demo: tuple[RunDir, Config], tmp_path: Path) -> None:
    import subprocess

    from gaphunter.errors import GapHunterError
    from gaphunter.importer import import_attack, import_baseline

    source, cfg = demo
    local = cfg.model_copy(update={"results_dir": tmp_path / "results"})
    run = RunDir.create(local, name="own")
    events = pd.concat([_events(source, f"baseline-{i:04d}") for i in (1, 2, 3)])
    evtx = tmp_path / "sysmon.evtx"
    evtx.write_bytes(b"placeholder")
    created = import_baseline(run, events, name="pc 01", slice_minutes=5, evtx_files=[evtx])
    assert created[0] == "baseline-pc_01-0001" and len(created) >= 4
    sessions = run.collected()
    assert {s.import_group for s in sessions} == {"pc_01"}
    assert sum(s.n_events or 0 for s in sessions) == len(events)
    assert (run.import_evtx_dir("pc_01") / "sysmon.evtx").is_file()
    with pytest.raises(GapHunterError, match="already exists"):
        import_baseline(run, events, name="pc 01", slice_minutes=5)
    mixed = events.copy()
    mixed.loc[mixed.index[:3], "host"] = "OTHER"
    with pytest.raises(GapHunterError, match="each host separately"):
        import_baseline(run, mixed, name="mixed", slice_minutes=5)

    execution_id = import_attack(
        run, _events(source, "T1082-1-r1"), technique="T1082", test=1, rep=1, root_pid=9001
    )
    assert execution_id == "T1082-1-r1" and run.get(execution_id).executor_root_pid == 9001  # type: ignore[union-attr]

    # Hayabusa runs once for the import; its alerts are assigned to slices by time.
    second = sessions[1]
    calls: list[list[str]] = []

    def fake_hayabusa(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if "--version" in argv:
            return subprocess.CompletedProcess(argv, 0, "Hayabusa v9.9.9\n", "")
        out = Path(argv[argv.index("-o") + 1])
        hit = {
            "Timestamp": (second.start_utc.isoformat()).replace("+00:00", "Z"),
            "RuleTitle": "t", "Level": "high", "Channel": "Sysmon", "RecordID": 1,
        }  # fmt: skip
        out.write_text(json.dumps(hit) + "\n" if "_imports" in " ".join(argv) else "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    rules = cfg.rules.model_copy(update={"hayabusa_bin": str(evtx)})  # any existing file
    alerts = run_rules(run, rules, runner=fake_hayabusa)
    assert alerts["execution_id"].tolist() == [second.execution_id]
    assert sum("_imports" in " ".join(c) for c in calls) == 1
    assert run.manifest()["tool_versions"]["hayabusa"] == "Hayabusa v9.9.9"
