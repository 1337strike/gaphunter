from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pandas as pd
import pytest

from gaphunter.config import FeatureConfig, LabelerConfig
from gaphunter.features import (
    bucket,
    feature_names,
    has_base64,
    session_windows,
    shannon_entropy,
    tokenize,
    window_features,
)
from gaphunter.labeler import label_events, lineage
from gaphunter.rundir import Session
from gaphunter.schema import EVENT_COLUMNS

T0 = datetime(2026, 11, 14, 2, 0, 0, tzinfo=UTC)
ROOT = 4000


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def ev(seconds: float, channel: str, event_id: int, **fields: Any) -> dict[str, Any]:
    row: dict[str, Any] = dict.fromkeys(EVENT_COLUMNS)
    row.update(execution_id="x", channel=channel, event_id=event_id, ts_utc=at(seconds))
    row.update(fields)
    return row


def frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    for i, row in enumerate(rows):
        row["record_id"] = i + 1
    df = pd.DataFrame(rows, columns=list(EVENT_COLUMNS))
    df["ts_utc"] = pd.to_datetime(df["ts_utc"], utc=True)
    return df


def create(
    seconds: float, pid: int, guid: str, ppid: int, pguid: str, cmd: str = "tool"
) -> dict[str, Any]:
    return ev(
        seconds, "sysmon", 1, pid=pid, process_guid=guid, parent_pid=ppid,
        parent_process_guid=pguid, image="C:\\bin\\tool.exe", command_line=cmd,
        parent_image="C:\\Windows\\System32\\cmd.exe", integrity_level="High",
    )  # fmt: skip


def session(**updates: Any) -> Session:
    base = Session(
        execution_id="x",
        kind="attack",
        technique_id="T1082",
        test_number=1,
        repetition=1,
        start_utc=at(0),
        end_utc=at(60),
        executor_root_pid=ROOT,
        control_pids=[777],
        status="collected",
    )
    return base.model_copy(update=updates)


def scenario() -> pd.DataFrame:
    return frame(
        [
            create(-5, 100, "{pre}", ROOT, "{root}"),  # 0 lineage, before the window
            create(5, 101, "{child}", ROOT, "{root}"),  # 1 child of root
            create(6, 102, "{grand}", 101, "{child}"),  # 2 grandchild
            ev(7, "sysmon", 13, pid=102, process_guid="{grand}", target_object="HKLM\\X"),  # 3
            ev(8, "security", 4688, pid=102, parent_pid=101),  # 4 PID-only, in lifetime
            ev(9, "powershell", 4104, pid=ROOT, script_block_text="root host code"),  # 5 root
            create(10, 500, "{other}", 50, "{svc}"),  # 6 unrelated process
            ev(11, "sysmon", 5, pid=102, process_guid="{grand}"),  # 7 grandchild exits
            ev(30, "security", 4688, pid=102, parent_pid=9),  # 8 PID reused later: not lineage
            ev(12, "powershell", 4104, pid=777, script_block_text="clock probe"),  # 9 control
            ev(70, "sysmon", 11, pid=101, process_guid="{child}", target_filename="C:\\a"),  # 10
        ]
    )


def test_lineage_recovers_root_from_children() -> None:
    roots, descendants = lineage(scenario(), ROOT)
    assert roots == {"{root}"}
    assert descendants == {"{pre}", "{child}", "{grand}"}


def test_label_requires_window_and_lineage() -> None:
    out, stats = label_events(scenario(), session(), LabelerConfig())
    assert stats.mode == "lineage"
    assert out["label"].tolist() == [
        False,  # lineage but before the window
        True, True, True, True, True,
        False,  # unrelated process inside the window
        True,
        False,  # same PID after the process exited
        False,  # GapHunter's own probe
        False,  # lineage but after the window
    ]  # fmt: skip
    assert out.loc[5, "label_reason"] == "lineage_root"
    assert out.loc[9, "label_reason"] == "control"
    assert out.loc[1, "technique_id"] == "T1082" and out.loc[6, "technique_id"] is None
    assert stats.n_malicious == 6 and stats.n_control == 1


def test_baseline_sessions_are_all_benign() -> None:
    out, stats = label_events(scenario(), session(kind="baseline"), LabelerConfig())
    assert not out["label"].any() and stats.mode == "baseline"
    assert out.loc[9, "label_reason"] == "control"


def test_missing_root_pid_uses_the_configured_fallback() -> None:
    noisy, stats = label_events(scenario(), session(executor_root_pid=None), LabelerConfig())
    assert stats.mode == "window_only"
    # every in-window event except the control probe
    assert noisy["label"].sum() == 8 and not noisy.loc[9, "label"]
    assert set(noisy.loc[noisy["label"], "label_reason"]) == {"window_only"}
    none, stats = label_events(
        scenario(), session(executor_root_pid=None), LabelerConfig(fallback="skip")
    )
    assert stats.mode == "skipped" and not none["label"].any()


def test_known_root_without_events_labels_nothing() -> None:
    out, stats = label_events(scenario(), session(executor_root_pid=31337), LabelerConfig())
    assert stats.mode == "no_lineage_events" and not out["label"].any()


# -- features ------------------------------------------------------------------------


def test_text_helpers() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abab") == pytest.approx(1.0)
    assert has_base64("x " + "QUJD" * 12) and not has_base64("whoami /all")
    mask = frozenset({"invoke-atomictest"})
    tokens = tokenize("Invoke-AtomicTest T1082 -TestNumbers 12 deadbeefdeadbeefdeadbeef", mask)
    assert "invoke-atomictest" not in " ".join(tokens)
    assert "<num>" in tokens and "<blob>" in tokens and "t1082" in tokens
    assert bucket("powershell.exe", 64) == bucket("powershell.exe", 64) == 19


def test_feature_names_are_fixed_and_unique() -> None:
    cfg = FeatureConfig()
    names = feature_names(cfg)
    assert len(names) == len(set(names))
    assert sum(n.startswith("f_tok_") for n in names) == cfg.token_buckets
    assert "rule_name" not in " ".join(names)


def test_window_features_counts() -> None:
    cfg = FeatureConfig()
    events = frame(
        [
            create(1, 10, "{a}", 1, "{p}", cmd="tool --data " + "QUJD" * 12),
            create(2, 11, "{b}", 1, "{p}", cmd="tool"),
            ev(
                3,
                "sysmon",
                13,
                pid=10,
                target_object="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\X",
            ),
            ev(
                3,
                "sysmon",
                13,
                pid=10,
                target_object="HKLM\\SYSTEM\\CurrentControlSet\\Services\\Y\\Start",
            ),
            ev(3, "sysmon", 12, pid=10, target_object="HKCU\\Software\\App\\Z"),
            ev(
                4, "sysmon", 11, pid=10, target_filename="C:\\Users\\u\\AppData\\Local\\Temp\\a.exe"
            ),
            ev(4, "sysmon", 3, pid=10, dest_ip="10.0.0.1", dest_port=443),
            ev(4, "sysmon", 3, pid=10, dest_ip="10.0.0.1", dest_port=80),
            ev(5, "powershell", 4104, pid=10, script_block_text="Get-Process"),
            ev(5, "security", 4688, pid=10),
            ev(5, "security", 9999, pid=10),
        ]
    )
    f = window_features(events, cfg)
    assert f["f_n_events"] == 11
    assert f["f_eid_sysmon_1"] == 2 and f["f_eid_sysmon_13"] == 2 and f["f_eid_sysmon_3"] == 2
    assert f["f_eid_security_4688"] == 1 and f["f_eid_security_other"] == 1
    assert f["f_proc_n_create"] == 2 and f["f_proc_high_integrity"] == 2
    assert f["f_proc_unique_images"] == 1  # both are tool.exe
    assert f["f_cmd_b64_count"] == 1 and f["f_cmd_len_max"] > f["f_cmd_len_mean"]
    assert (f["f_reg_run"], f["f_reg_services"], f["f_reg_other"]) == (1, 1, 1)
    assert f["f_file_n"] == 1 and f["f_file_exec_ext"] == 1 and f["f_file_temp"] == 1
    assert f["f_net_n"] == 2 and f["f_net_unique_ips"] == 1 and f["f_net_unique_ports"] == 2
    assert f["f_ps_n_blocks"] == 1
    assert sum(v for k, v in f.items() if k.startswith("f_img_")) == 2
    assert sum(v for k, v in f.items() if k.startswith("f_tok_")) > 0


def test_session_windows_labels_and_exclusions() -> None:
    labeled, _ = label_events(scenario(), session(), LabelerConfig())
    windows = session_windows(labeled, session(), FeatureConfig(window_s=30))
    assert windows["window_id"].tolist() == ["x:00000", "x:00001"]
    first, second = windows.iloc[0], windows.iloc[1]
    # window 0: events 1,2,3,4,6,7 (root host event and control probe are dropped)
    assert first["n_events"] == 6 and first["n_malicious_events"] == 5
    assert bool(first["label"]) and first["technique_id"] == "T1082"
    assert first["first_malicious_ts"] == pd.Timestamp(at(5))
    assert first["window_start"] == pd.Timestamp(at(0))
    assert first["window_end"] == pd.Timestamp(at(30))
    # window 1: only the reused-PID event, which is benign
    assert second["n_events"] == 1 and not bool(second["label"])
    assert pd.isna(second["technique_id"])

    keep_root = session_windows(labeled, session(), FeatureConfig(exclude_root_process=False))
    assert keep_root.iloc[0]["n_events"] == 7
