"""Deployable models: train once on a run, then score new logs and explain the alerts.

A :class:`ModelBundle` is everything needed to score logs elsewhere: the feature settings,
the fitted preprocessor, one or more fitted detectors and the alert threshold. It is saved
with joblib.

SECURITY: a bundle is a pickle. Loading one executes code from the file, so only load
bundles that you (or people you trust) created with GapHunter.

Detection works on whole .evtx exports: parse, cut into windows on a fixed time grid per
host, score, and emit one alert per window above the threshold together with the reasons
(which features deviate from the benign baseline, which strings are behind them, and which
command lines in the window are the rarest).
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from gaphunter import __version__
from gaphunter.collector.parse import parse_evtx
from gaphunter.collector.store import dedupe_and_sort
from gaphunter.config import Config, DetectConfig, FeatureConfig
from gaphunter.detectors.ml import (
    FloatArray,
    Preprocessor,
    grid_for,
    make_detector,
    robust_scale,
    split_windows,
    uses_raw,
)
from gaphunter.errors import GapHunterError
from gaphunter.features import (
    EVENT_IDS,
    basename,
    bucket,
    bucket_members,
    feature_columns,
    session_windows,
    tokenize,
)
from gaphunter.log import get_logger
from gaphunter.rundir import RunDir, Session
from gaphunter.schema import EVENT_COLUMNS

log = get_logger(__name__)

BUNDLE_FORMAT = 1

FEATURE_DESCRIPTIONS: dict[str, str] = {
    "f_n_events": "events in the window",
    "f_proc_n_create": "processes started",
    "f_proc_unique_images": "distinct programs started",
    "f_proc_unique_parents": "distinct parent programs",
    "f_proc_unique_pairs": "distinct parent>child pairs",
    "f_proc_high_integrity": "processes started with High integrity",
    "f_proc_system_integrity": "processes started as System",
    "f_proc_max_depth": "longest chain of processes starting processes",
    "f_proc_max_children": "most processes started by one parent",
    "f_proc_user_writable": "programs run from user-writable folders",
    "f_proc_script_host": "script hosts / shells started",
    "f_cmd_n": "command lines",
    "f_cmd_len_mean": "average command-line length",
    "f_cmd_len_max": "longest command line",
    "f_cmd_entropy_mean": "average command-line entropy",
    "f_cmd_entropy_max": "highest command-line entropy",
    "f_cmd_special_ratio_max": "highest share of special characters in a command line",
    "f_cmd_digit_ratio_max": "highest share of digits in a command line",
    "f_cmd_b64_count": "command lines with base64-like strings",
    "f_cmd_long_count": "very long command lines",
    "f_ps_n_blocks": "PowerShell script blocks",
    "f_ps_len_max": "longest PowerShell script block",
    "f_ps_entropy_max": "highest PowerShell script entropy",
    "f_ps_b64_count": "PowerShell blocks with base64-like strings",
    "f_reg_run": "registry writes to Run keys",
    "f_reg_services": "registry writes to service keys",
    "f_reg_policies": "registry writes to policy keys",
    "f_reg_classes": "registry writes to class/COM keys",
    "f_reg_ifeo": "registry writes to Image File Execution Options",
    "f_reg_security": "registry writes to SAM/LSA keys",
    "f_reg_other": "other registry writes",
    "f_file_n": "files created or deleted",
    "f_file_exec_ext": "executable files written",
    "f_file_script_ext": "script files written",
    "f_file_temp": "files written to temp folders",
    "f_file_startup": "files written to the Startup folder",
    "f_file_system": "files written under C:\\Windows",
    "f_net_n": "network connections",
    "f_net_unique_ips": "distinct destination addresses",
    "f_net_unique_ports": "distinct destination ports",
    "f_dns_n": "DNS queries",
    "f_procaccess_n": "process-access events",
    "f_remote_thread_n": "remote-thread events",
}


def describe_feature(name: str) -> str:
    if name in FEATURE_DESCRIPTIONS:
        return FEATURE_DESCRIPTIONS[name]
    if name.startswith("f_eid_"):
        _, _, channel, eid = name.split("_", 3)
        if eid == "other":
            return f"other {channel} events"
        known = EVENT_IDS.get(channel, ())
        return f"{channel} event {eid}" if int(eid) in known else name
    if name.startswith("f_tok_"):
        return "command-line / script words"
    if name.startswith("f_img_"):
        return "program names"
    if name.startswith("f_pair_"):
        return "parent>child program pairs"
    return name


@dataclass
class Member:
    detector: str
    config_id: str
    params: dict[str, Any]
    model: Any
    loc: float = 0.0
    scale: float = 1.0


@dataclass
class ModelBundle:
    name: str
    feature_config: dict[str, Any]
    columns: list[str]
    preprocessor: Preprocessor
    members: list[Member]
    threshold: float
    target_fpr: float
    val_spread: float
    meta: dict[str, Any] = field(default_factory=dict)
    format: int = BUNDLE_FORMAT

    def features(self) -> FeatureConfig:
        return FeatureConfig.model_validate(self.feature_config)

    def member_scores(self, x: FloatArray) -> list[FloatArray]:
        z = self.preprocessor.transform(x)
        return [
            (m.model.score(x if uses_raw(m.model) else z) - m.loc) / m.scale for m in self.members
        ]

    def score(self, x: FloatArray) -> FloatArray:
        return np.asarray(np.mean(self.member_scores(x), axis=0), dtype=np.float64)

    def severity(self, score: float) -> str:
        """low / medium / high from how far the score is past the threshold."""
        excess = (score - self.threshold) / self.val_spread
        return "high" if excess >= 3 else "medium" if excess >= 1 else "low"


# -- building ------------------------------------------------------------------------


def _pick_config(
    detector: str,
    config: Config,
    columns: list[str],
    x: FloatArray,
    z: FloatArray,
    train: np.ndarray[Any, Any],
    val: np.ndarray[Any, Any],
    malicious: np.ndarray[Any, Any],
    seed: int,
) -> Member:
    """Fit every grid entry; keep the best by average precision if attack data exists."""
    best: tuple[float, Member, FloatArray] | None = None
    for index, params in enumerate(grid_for(config.ml, detector)):
        model = make_detector(config.ml, detector, params, seed, columns)
        raw = uses_raw(model)
        model.fit(x[train] if raw else z[train])
        scores = model.score(x if raw else z)
        quality = 0.0
        if malicious.any():
            y = np.r_[np.ones(int(malicious.sum())), np.zeros(int(val.sum()))]
            quality = float(average_precision_score(y, np.r_[scores[malicious], scores[val]]))
        if best is None or quality > best[0] + 1e-12:
            best = (quality, Member(detector, f"{detector}#{index}", dict(params), model), scores)
    assert best is not None
    _, member, scores = best
    member.loc, member.scale = robust_scale(scores[train])
    return member


def fit_bundle(run: RunDir, config: Config, detector: str) -> ModelBundle:
    """Train a deployable model on a run's benign windows.

    ``detector`` is one of ``ml.detectors`` or ``ensemble``. Unlike the evaluation (which
    is leave-technique-out), the deployed model may use every labelled technique of the
    run to choose among hyper-parameter entries; its threshold still comes from benign
    validation windows only.
    """
    if not run.windows_path.is_file():
        raise GapHunterError("windows.parquet not found; run 'gaphunter features' first")
    names = list(config.ml.detectors) if detector == "ensemble" else [detector]
    unknown = [n for n in names if n not in config.ml.detectors]
    if unknown:
        raise GapHunterError(f"detector {unknown[0]!r} is not enabled in ml.detectors")
    windows = pd.read_parquet(run.windows_path)
    columns = feature_columns(windows)
    split = split_windows(windows, config.ml, config.seed)["split"].to_numpy()
    train, val = split == "train", split == "val"
    malicious = windows["label"].to_numpy(dtype=bool)
    x = windows[columns].to_numpy(dtype=np.float64)
    prep = Preprocessor(columns).fit(x[train])
    z = prep.transform(x)
    seed = config.ml.seeds[0]
    members = [_pick_config(n, config, columns, x, z, train, val, malicious, seed) for n in names]
    bundle = ModelBundle(
        name=detector,
        feature_config=config.features.model_dump(mode="json"),
        columns=columns,
        preprocessor=prep,
        members=members,
        threshold=0.0,
        target_fpr=config.ml.target_fpr,
        val_spread=1.0,
    )
    val_scores = bundle.score(x[val])
    bundle.threshold = float(np.quantile(val_scores, 1.0 - config.ml.target_fpr, method="higher"))
    bundle.val_spread = robust_scale(val_scores)[1]
    manifest = run.manifest()
    bundle.meta = {
        "gaphunter_version": __version__,
        "created_utc": datetime.now(UTC).isoformat(),
        "source_run": manifest.get("run_id"),
        "synthetic": bool(manifest.get("synthetic", False)),
        "seed": seed,
        "n_train_windows": int(train.sum()),
        "n_val_windows": int(val.sum()),
        "n_malicious_windows_seen": int(malicious.sum()),
        "members": [{"detector": m.detector, "config": m.config_id, **m.params} for m in members],
        "tool_versions": manifest.get("tool_versions", {}),
        "guest": manifest.get("guest", {}),
    }
    log.info("bundle.fitted", name=detector, threshold=round(bundle.threshold, 4))
    return bundle


def save_bundle(bundle: ModelBundle, path: Path) -> Path:
    """Write ``path`` (joblib) and a human-readable ``path.json`` next to it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path, compress=3)
    card = {
        "name": bundle.name,
        "format": bundle.format,
        "threshold": bundle.threshold,
        "target_fpr": bundle.target_fpr,
        "n_features": len(bundle.columns),
        "feature_config": bundle.feature_config,
        **bundle.meta,
    }
    Path(str(path) + ".json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    return path


def load_bundle(path: Path) -> ModelBundle:
    if not path.is_file():
        raise GapHunterError(f"model bundle not found: {path}")
    try:
        bundle = joblib.load(path)
    except Exception as exc:  # noqa: BLE001 - any unpickling failure is a bad bundle
        raise GapHunterError(f"cannot load model bundle {path}: {exc}") from exc
    if not isinstance(bundle, ModelBundle):
        raise GapHunterError(f"{path} is not a GapHunter model bundle")
    if bundle.format != BUNDLE_FORMAT:
        raise GapHunterError(
            f"{path} has bundle format {bundle.format}, this version reads {BUNDLE_FORMAT}"
        )
    return bundle


# -- explanations --------------------------------------------------------------------


def _contributions(bundle: ModelBundle, x_row: FloatArray) -> dict[str, float]:
    """How much each feature pushes this window away from benign, on a common scale.

    Deviation from the benign baseline in preprocessed units (absolute z-score for
    numeric features, TF-IDF weight for word buckets), plus, when present, the
    autoencoder's per-feature reconstruction error and the rarity detector's surprise.
    Each source is normalised to sum to one before averaging.
    """
    prep = bundle.preprocessor
    z = prep.transform(x_row[None, :])
    names = prep.output_columns
    sources: list[dict[str, float]] = [dict(zip(names, np.abs(z[0]), strict=True))]
    for member in bundle.members:
        model = member.model
        if hasattr(model, "feature_errors"):
            sources.append(dict(zip(names, model.feature_errors(z)[0], strict=True)))
        elif hasattr(model, "surprise"):
            idx = model._idx  # noqa: SLF001 - same package
            values = model.surprise(x_row[None, :])[0]
            sources.append({bundle.columns[i]: float(v) for i, v in zip(idx, values, strict=True)})
    total: dict[str, float] = {}
    for source in sources:
        norm = sum(source.values())
        if norm > 0:
            for name, value in source.items():
                total[name] = total.get(name, 0.0) + float(value) / norm / len(sources)
    return total


def _rare_commands(
    bundle: ModelBundle, events: pd.DataFrame, cfg: DetectConfig
) -> list[dict[str, Any]]:
    """Command lines and script blocks ranked by how unusual their words are in benign data."""
    if cfg.top_commands == 0 or events.empty:
        return []
    features = bundle.features()
    idf = bundle.preprocessor.idf()
    mask = frozenset(m.lower() for m in features.mask_tokens)
    floor = min(idf.values()) if idf else 0.0
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in events.itertuples(index=False):
        text = record.command_line if isinstance(record.command_line, str) else None
        kind = "command"
        if text is None and isinstance(record.script_block_text, str):
            text, kind = record.script_block_text, "script"
        if not text or text in seen:
            continue
        seen.add(text)
        tokens = tokenize(text, mask)
        if not tokens:
            continue
        weights = [idf.get(f"f_tok_{bucket(t, features.token_buckets):03d}", floor) for t in tokens]
        rows.append(
            {
                "kind": kind,
                "rarity": round(float(np.mean(weights)) - floor, 3),
                "time": record.ts_utc.isoformat(),
                "image": record.image if isinstance(record.image, str) else None,
                "parent_image": record.parent_image
                if isinstance(record.parent_image, str)
                else None,
                "pid": None if pd.isna(record.pid) else int(record.pid),
                "user": record.user if isinstance(record.user, str) else None,
                "text": text[: cfg.max_command_chars],
            }
        )
    rows.sort(key=lambda r: r["rarity"], reverse=True)
    return rows[: cfg.top_commands]


def explain_window(
    bundle: ModelBundle, x_row: FloatArray, events: pd.DataFrame, cfg: DetectConfig
) -> dict[str, Any]:
    """Why a window scored the way it did, in terms an analyst can check in the logs."""
    features = bundle.features()
    contributions = _contributions(bundle, x_row)
    benign = bundle.preprocessor.benign_mean()
    members = bucket_members(events, features) if not events.empty else {}
    values = dict(zip(bundle.columns, x_row, strict=True))
    ranked = sorted(contributions.items(), key=lambda kv: kv[1], reverse=True)
    top: list[dict[str, Any]] = []
    for name, weight in ranked:
        if len(top) >= cfg.top_features or weight <= 0:
            break
        if values.get(name, 0.0) == 0 and name not in benign:
            continue  # an absent word bucket cannot be a reason
        item: dict[str, Any] = {
            "feature": name,
            "what": describe_feature(name),
            "value": round(float(values.get(name, 0.0)), 3),
            "share": round(float(weight), 4),
        }
        if name in benign:
            item["benign_typical"] = round(benign[name], 3)
        if name in members:
            item["examples"] = [text for text, _ in members[name].most_common(5)]
        top.append(item)
    # Sysmon 1 and Security 4688 both record a process start: count each start once.
    creates = events[(events["channel"] == "sysmon") & (events["event_id"] == 1)]
    if creates.empty:
        creates = events[(events["channel"] == "security") & (events["event_id"] == 4688)]
    programs = Counter(basename(v) for v in creates["image"] if isinstance(v, str))
    return {
        "top_features": top,
        "rarest_commands": _rare_commands(bundle, events, cfg),
        "programs_started": [{"image": k, "count": v} for k, v in programs.most_common(8)],
    }


# -- detection -----------------------------------------------------------------------


def events_frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    """Rows from the parser as an events frame (no labels: these are logs to be judged)."""
    frame = pd.DataFrame(dedupe_and_sort(rows), columns=list(EVENT_COLUMNS))
    frame["ts_utc"] = pd.to_datetime(frame["ts_utc"], utc=True)
    frame["label"] = False
    return frame


def read_evtx_files(paths: list[Path], execution_id: str = "detect") -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            raise GapHunterError(f"file not found: {path}")
        rows.extend(parse_evtx(path, execution_id=execution_id))
    return events_frame(rows)


def detect_events(
    events: pd.DataFrame, bundle: ModelBundle, cfg: DetectConfig, *, explain: bool = True
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Score events and return ``(alerts, summary)``. One alert per window over threshold."""
    features = bundle.features()
    width = pd.Timedelta(seconds=features.window_s)
    alerts: list[dict[str, Any]] = []
    n_windows = 0
    hosts = events["host"].fillna("unknown") if not events.empty else pd.Series(dtype=object)
    for host, part in events.groupby(hosts, sort=True):
        start = part["ts_utc"].min().floor(f"{int(features.window_s)}s")
        end = part["ts_utc"].max()
        session = Session(
            execution_id=str(host),
            kind="baseline",
            start_utc=start.to_pydatetime(),
            end_utc=end.to_pydatetime(),
            status="collected",
        )
        windows = session_windows(part, session, features)
        if windows.empty:
            continue
        missing = [c for c in bundle.columns if c not in windows.columns]
        if missing:
            raise GapHunterError(
                f"model expects feature {missing[0]!r}, which this version does not produce; "
                "retrain the model with this GapHunter version"
            )
        x = windows[bundle.columns].to_numpy(dtype=np.float64)
        scores = bundle.score(x)
        n_windows += len(windows)
        for i in np.flatnonzero(scores > bundle.threshold):
            row = windows.iloc[int(i)]
            window_start = pd.Timestamp(row["window_start"])
            chunk = part[(part["ts_utc"] >= window_start) & (part["ts_utc"] < window_start + width)]
            alert: dict[str, Any] = {
                "type": "ml",
                "host": str(host),
                "window_start": window_start.isoformat(),
                "window_end": (window_start + width).isoformat(),
                "detector": bundle.name,
                "score": round(float(scores[i]), 4),
                "threshold": round(bundle.threshold, 4),
                "severity": bundle.severity(float(scores[i])),
                "n_events": int(row["n_events"]),
            }
            if explain:
                alert["explanation"] = explain_window(bundle, x[int(i)], chunk, cfg)
            alerts.append(alert)
    alerts.sort(key=lambda a: (a["window_start"], a["host"]))
    alert_rate = len(alerts) / n_windows if n_windows else 0.0
    summary: dict[str, Any] = {
        "model": bundle.name,
        "model_created_utc": bundle.meta.get("created_utc"),
        "model_synthetic": bool(bundle.meta.get("synthetic", False)),
        "events": int(len(events)),
        "hosts": int(hosts.nunique()) if not events.empty else 0,
        "windows": n_windows,
        "alerts": len(alerts),
        "expected_false_alerts": round(n_windows * bundle.target_fpr, 2),
        "alert_rate": round(alert_rate, 4),
    }
    # Far more alerts than the threshold allows means the logs do not look like the
    # model's baseline at all (other host role, other Sysmon config, other OS build).
    summary["baseline_mismatch"] = bool(
        n_windows >= 20 and alert_rate > max(0.2, 10 * bundle.target_fpr)
    )
    return alerts, summary


def render_alert(alert: dict[str, Any]) -> str:
    """Plain-text rendering of one alert for the terminal."""
    if alert.get("type") == "rule":
        return (
            f"[{alert['severity'].upper():<6}] {alert['time']}  {alert.get('host') or ''}  "
            f"RULE  {alert['rule_title']}  {' '.join(alert.get('mitre_tags', []))}"
        ).rstrip()
    lines = [
        f"[{alert['severity'].upper():<6}] {alert['window_start']}  {alert['host']}  "
        f"score {alert['score']} > {alert['threshold']}  ({alert['n_events']} events)"
    ]
    explanation = alert.get("explanation") or {}
    for item in explanation.get("top_features", []):
        detail = f"    - {item['what']}: {item['value']:g}"
        if "benign_typical" in item:
            detail += f" (benign ~{item['benign_typical']:g})"
        if item.get("examples"):
            detail += "  e.g. " + ", ".join(item["examples"][:3])
        lines.append(detail)
    for command in explanation.get("rarest_commands", [])[:3]:
        lines.append(f"    > {command['text'][:160]}")
    return "\n".join(lines)
