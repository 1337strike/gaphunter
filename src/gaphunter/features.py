"""Per-window feature extraction.

Each session is cut into fixed-length windows aligned to its start. One row per non-empty
window is written to ``windows.parquet``: identity and label columns (see
``schema.WINDOW_META_COLUMNS``) followed by raw, un-normalised features (``f_*``).

Nothing here is fitted to data: counts, text statistics and hashed bag-of-words buckets
are pure functions of the events in the window. Everything that *is* fitted (IDF weights,
scaling) lives in the detector pipeline and only ever sees benign training windows.

Leakage guards:

* ``rule_name`` is never read (sysmon-modular stores ATT&CK IDs there);
* tokens naming the emulation framework are masked;
* GapHunter's own control processes are dropped, and by default so are the events of the
  lineage root process itself (the framework's host process).
"""

from __future__ import annotations

import math
import re
import zlib
from collections import Counter
from collections.abc import Iterable

import numpy as np
import pandas as pd

from gaphunter.collector.store import read_events
from gaphunter.config import FeatureConfig
from gaphunter.errors import GapHunterError
from gaphunter.log import get_logger
from gaphunter.rundir import RunDir, Session

log = get_logger(__name__)

EVENT_IDS: dict[str, tuple[int, ...]] = {
    "sysmon": (1, 3, 5, 7, 8, 10, 11, 12, 13, 15, 17, 18, 22, 23, 25, 26),
    "security": (4624, 4625, 4648, 4656, 4663, 4672, 4688, 4689, 4697, 4698, 4699, 4702,
                 4720, 4722, 4724, 4728, 4732, 4738, 5140, 5145, 5156),
    "powershell": (4103, 4104, 40961, 40962, 53504),
}  # fmt: skip

_REG_CATEGORIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("run", re.compile(r"\\currentversion\\(run|runonce|explorer\\shell folders)", re.I)),
    ("services", re.compile(r"\\(currentcontrolset|controlset\d+)\\services\\", re.I)),
    ("policies", re.compile(r"\\policies\\", re.I)),
    ("classes", re.compile(r"\\(software\\classes|clsid)\\|^hkcr", re.I)),
    ("ifeo", re.compile(r"\\image file execution options\\", re.I)),
    ("security", re.compile(r"\\(sam|security)\\|\\control\\(lsa|securityproviders)", re.I)),
)
_EXEC_EXT = (".exe", ".dll", ".sys", ".scr", ".com", ".msi")
_SCRIPT_EXT = (".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".wsf")
_TOKEN = re.compile(r"[a-z0-9][a-z0-9_\-]{1,63}")
_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_SPECIAL = re.compile(r"[^A-Za-z0-9\s\\/:.\-_]")
_HEXBLOB = re.compile(r"^[0-9a-f]{16,}$")
_USER_WRITABLE = re.compile(r"\\(users|programdata|temp|tmp|appdata|public)\\", re.I)
_SCRIPT_HOSTS = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
    }
)
_LONG_COMMAND = 300

STAT_FEATURES: tuple[str, ...] = (
    "f_n_events",
    "f_proc_n_create",
    "f_proc_unique_images",
    "f_proc_unique_parents",
    "f_proc_unique_pairs",
    "f_proc_high_integrity",
    "f_proc_system_integrity",
    "f_cmd_n",
    "f_cmd_len_mean",
    "f_cmd_len_max",
    "f_cmd_entropy_mean",
    "f_cmd_entropy_max",
    "f_cmd_special_ratio_max",
    "f_cmd_digit_ratio_max",
    "f_cmd_b64_count",
    "f_ps_n_blocks",
    "f_ps_len_max",
    "f_ps_entropy_max",
    "f_ps_b64_count",
    "f_reg_run",
    "f_reg_services",
    "f_reg_policies",
    "f_reg_classes",
    "f_reg_ifeo",
    "f_reg_security",
    "f_reg_other",
    "f_file_n",
    "f_file_exec_ext",
    "f_file_script_ext",
    "f_file_temp",
    "f_file_startup",
    "f_file_system",
    "f_net_n",
    "f_net_unique_ips",
    "f_net_unique_ports",
    "f_dns_n",
    "f_procaccess_n",
    "f_remote_thread_n",
    # process-tree shape and launch context (added in 0.2)
    "f_proc_max_depth",
    "f_proc_max_children",
    "f_proc_user_writable",
    "f_proc_script_host",
    "f_cmd_long_count",
)


def feature_names(cfg: FeatureConfig) -> list[str]:
    """All feature columns, in a fixed order."""
    names = list(STAT_FEATURES)
    for channel, ids in EVENT_IDS.items():
        names += [f"f_eid_{channel}_{eid}" for eid in ids]
        names.append(f"f_eid_{channel}_other")
    names += [f"f_tok_{i:03d}" for i in range(cfg.token_buckets)]
    names += [f"f_img_{i:02d}" for i in range(cfg.name_buckets)]
    names += [f"f_pair_{i:02d}" for i in range(cfg.name_buckets)]
    return names


# -- text helpers --------------------------------------------------------------------


def shannon_entropy(text: str) -> float:
    """Character-level Shannon entropy in bits."""
    if not text:
        return 0.0
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in Counter(text).values())


def special_ratio(text: str) -> float:
    return len(_SPECIAL.findall(text)) / len(text) if text else 0.0


def digit_ratio(text: str) -> float:
    return sum(ch.isdigit() for ch in text) / len(text) if text else 0.0


def has_base64(text: str) -> bool:
    return bool(_B64.search(text))


def tokenize(text: str, mask: frozenset[str]) -> list[str]:
    """Lower-case word tokens; numbers and long hex blobs are collapsed; masks removed."""
    lowered = text.lower()
    for word in mask:
        lowered = lowered.replace(word, " ")
    tokens: list[str] = []
    for token in _TOKEN.findall(lowered):
        if token.isdigit():
            tokens.append("<num>")
        elif _HEXBLOB.match(token) or len(token) > 40:
            tokens.append("<blob>")
        else:
            tokens.append(token)
    return tokens


def bucket(text: str, n_buckets: int) -> int:
    """Stable hash bucket (CRC32, independent of PYTHONHASHSEED)."""
    return zlib.crc32(text.encode("utf-8", "replace")) % n_buckets


def basename(path: object) -> str:
    if not isinstance(path, str) or not path:
        return ""
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


# -- one window ----------------------------------------------------------------------


def _strings(series: pd.Series) -> list[str]:
    return [v for v in series if isinstance(v, str) and v]


def _process_keys(creates: pd.DataFrame) -> list[tuple[object, object]]:
    """(process, parent) identity per process creation: GUIDs when present, else PIDs."""
    keys: list[tuple[object, object]] = []
    for guid, parent_guid, pid, parent_pid in zip(
        creates["process_guid"],
        creates["parent_process_guid"],
        creates["pid"],
        creates["parent_pid"],
        strict=True,
    ):
        own = guid if isinstance(guid, str) else (None if pd.isna(pid) else int(pid))
        parent = (
            parent_guid
            if isinstance(parent_guid, str)
            else (None if pd.isna(parent_pid) else int(parent_pid))
        )
        keys.append((own, parent))
    return keys


def _tree_shape(creates: pd.DataFrame) -> tuple[float, float]:
    """Longest parent-child chain and largest fan-out among the window's new processes."""
    keys = _process_keys(creates)
    if not keys:
        return 0.0, 0.0
    parent_of = {own: parent for own, parent in keys if own is not None}
    fan_out = Counter(parent for _, parent in keys if parent is not None)
    depth_cache: dict[object, int] = {}

    def depth(node: object) -> int:
        chain: list[object] = []
        while node in parent_of and node not in depth_cache and node not in chain:
            chain.append(node)
            node = parent_of[node]
        base = depth_cache.get(node, 0)
        for offset, item in enumerate(reversed(chain), start=1):
            depth_cache[item] = base + offset
        return depth_cache.get(chain[0], base) if chain else base

    deepest = max(depth(own) for own in parent_of) if parent_of else 1
    return float(deepest), float(max(fan_out.values(), default=0))


def bucket_members(events: pd.DataFrame, cfg: FeatureConfig) -> dict[str, Counter[str]]:
    """Which raw tokens / image names / parent>child pairs fell into each hashed feature.

    Hashed features are opaque on their own; explanations use this to show the analyst
    the actual strings behind a bucket.
    """
    mask = frozenset(m.lower() for m in cfg.mask_tokens)
    channel, event_id = events["channel"], events["event_id"]
    creates = events[(channel == "sysmon") & (event_id == 1)]
    if creates.empty:
        creates = events[(channel == "security") & (event_id == 4688)]
    members: dict[str, Counter[str]] = {}
    images = [basename(v) for v in creates["image"]]
    parents = [basename(v) for v in creates["parent_image"]]
    for image in images:
        if image:
            members.setdefault(f"f_img_{bucket(image, cfg.name_buckets):02d}", Counter())[
                image
            ] += 1
    for parent, image in zip(parents, images, strict=True):
        pair = f"{parent}>{image}"
        members.setdefault(f"f_pair_{bucket(pair, cfg.name_buckets):02d}", Counter())[pair] += 1
    texts = (
        *_strings(creates["command_line"]),
        *_strings(events.loc[channel == "powershell", "script_block_text"]),
    )
    for text in texts:
        for token in tokenize(text, mask):
            members.setdefault(f"f_tok_{bucket(token, cfg.token_buckets):03d}", Counter())[
                token
            ] += 1
    return members


def window_features(events: pd.DataFrame, cfg: FeatureConfig) -> dict[str, float]:
    """Feature vector for the events of one window."""
    mask = frozenset(m.lower() for m in cfg.mask_tokens)
    feats: dict[str, float] = dict.fromkeys(feature_names(cfg), 0.0)
    feats["f_n_events"] = float(len(events))
    channel = events["channel"]
    event_id = events["event_id"]

    for name, ids in EVENT_IDS.items():
        counts = event_id[channel == name].value_counts()
        other = 0
        for eid, count in counts.items():
            if eid in ids:
                feats[f"f_eid_{name}_{eid}"] = float(count)
            else:
                other += int(count)
        feats[f"f_eid_{name}_other"] = float(other)

    sysmon = channel == "sysmon"
    creates = events[sysmon & (event_id == 1)]
    if creates.empty:  # no Sysmon coverage in this window: fall back to Security 4688
        creates = events[(channel == "security") & (event_id == 4688)]
    images = [basename(v) for v in creates["image"]]
    parents = [basename(v) for v in creates["parent_image"]]
    pairs = [f"{p}>{i}" for p, i in zip(parents, images, strict=True)]
    feats["f_proc_n_create"] = float(len(creates))
    feats["f_proc_unique_images"] = float(len({i for i in images if i}))
    feats["f_proc_unique_parents"] = float(len({p for p in parents if p}))
    feats["f_proc_unique_pairs"] = float(len(set(pairs)))
    integrity = creates["integrity_level"]
    feats["f_proc_high_integrity"] = float((integrity == "High").sum())
    feats["f_proc_system_integrity"] = float((integrity == "System").sum())
    feats["f_proc_max_depth"], feats["f_proc_max_children"] = _tree_shape(creates)
    feats["f_proc_user_writable"] = float(
        sum(bool(_USER_WRITABLE.search(v)) for v in _strings(creates["image"]))
    )
    feats["f_proc_script_host"] = float(sum(i in _SCRIPT_HOSTS for i in images))
    for image in images:
        if image:
            feats[f"f_img_{bucket(image, cfg.name_buckets):02d}"] += 1.0
    for pair in pairs:
        feats[f"f_pair_{bucket(pair, cfg.name_buckets):02d}"] += 1.0

    commands = _strings(creates["command_line"])
    if commands:
        lengths = [len(c) for c in commands]
        entropies = [shannon_entropy(c) for c in commands]
        feats["f_cmd_n"] = float(len(commands))
        feats["f_cmd_len_mean"] = float(np.mean(lengths))
        feats["f_cmd_len_max"] = float(max(lengths))
        feats["f_cmd_entropy_mean"] = float(np.mean(entropies))
        feats["f_cmd_entropy_max"] = float(max(entropies))
        feats["f_cmd_special_ratio_max"] = max(special_ratio(c) for c in commands)
        feats["f_cmd_digit_ratio_max"] = max(digit_ratio(c) for c in commands)
        feats["f_cmd_b64_count"] = float(sum(has_base64(c) for c in commands))
        feats["f_cmd_long_count"] = float(sum(n > _LONG_COMMAND for n in lengths))

    blocks = _strings(events.loc[channel == "powershell", "script_block_text"])
    if blocks:
        feats["f_ps_n_blocks"] = float(len(blocks))
        feats["f_ps_len_max"] = float(max(len(b) for b in blocks))
        feats["f_ps_entropy_max"] = max(shannon_entropy(b) for b in blocks)
        feats["f_ps_b64_count"] = float(sum(has_base64(b) for b in blocks))

    for text in (*commands, *blocks):
        for token in tokenize(text, mask):
            feats[f"f_tok_{bucket(token, cfg.token_buckets):03d}"] += 1.0

    for target in _strings(events.loc[sysmon & event_id.isin([12, 13, 14]), "target_object"]):
        for name, pattern in _REG_CATEGORIES:
            if pattern.search(target):
                feats[f"f_reg_{name}"] += 1.0
                break
        else:
            feats["f_reg_other"] += 1.0

    files = _strings(events.loc[sysmon & event_id.isin([11, 15, 23, 26]), "target_filename"])
    feats["f_file_n"] = float(len(files))
    for path in files:
        lower = path.lower()
        feats["f_file_exec_ext"] += float(lower.endswith(_EXEC_EXT))
        feats["f_file_script_ext"] += float(lower.endswith(_SCRIPT_EXT))
        feats["f_file_temp"] += float("\\temp\\" in lower or "\\tmp\\" in lower)
        feats["f_file_startup"] += float("\\start menu\\programs\\startup" in lower)
        feats["f_file_system"] += float(lower.startswith("c:\\windows\\"))

    net = events[sysmon & (event_id == 3)]
    feats["f_net_n"] = float(len(net))
    feats["f_net_unique_ips"] = float(net["dest_ip"].nunique())
    feats["f_net_unique_ports"] = float(net["dest_port"].nunique())
    feats["f_dns_n"] = float((sysmon & (event_id == 22)).sum())
    feats["f_procaccess_n"] = float((sysmon & (event_id == 10)).sum())
    feats["f_remote_thread_n"] = float((sysmon & (event_id == 8)).sum())
    return feats


# -- sessions and runs ---------------------------------------------------------------


def session_windows(events: pd.DataFrame, session: Session, cfg: FeatureConfig) -> pd.DataFrame:
    """Cut one labelled session into windows and compute features for each."""
    columns = [
        "window_id", "execution_id", "source", "window_start", "window_end", "label",
        "technique_id", "n_events", "n_malicious_events", "first_malicious_ts",
        *feature_names(cfg),
    ]  # fmt: skip
    if session.end_utc is None or events.empty:
        return pd.DataFrame(columns=columns)
    start = pd.Timestamp(session.start_utc)
    end = pd.Timestamp(session.end_utc)
    drop = {"control"} | ({"lineage_root"} if cfg.exclude_root_process else set())
    keep = (
        (events["ts_utc"] >= start) & (events["ts_utc"] <= end) & ~events["label_reason"].isin(drop)
    )
    frame = events[keep]
    if frame.empty:
        return pd.DataFrame(columns=columns)
    width = pd.Timedelta(seconds=cfg.window_s)
    index = ((frame["ts_utc"] - start) // width).astype(int)
    rows: list[dict[str, object]] = []
    for k, chunk in frame.groupby(index, sort=True):
        malicious = chunk[chunk["label"].fillna(False).astype(bool)]
        row: dict[str, object] = {
            "window_id": f"{session.execution_id}:{int(k):05d}",
            "execution_id": session.execution_id,
            "source": session.kind,
            "window_start": start + int(k) * width,
            "window_end": start + (int(k) + 1) * width,
            "label": not malicious.empty,
            "technique_id": session.technique_id if not malicious.empty else None,
            "n_events": len(chunk),
            "n_malicious_events": len(malicious),
            "first_malicious_ts": malicious["ts_utc"].min() if not malicious.empty else pd.NaT,
        }
        row.update(window_features(chunk, cfg))
        rows.append(row)
    return pd.DataFrame(rows, columns=columns)


def build_windows(run: RunDir, cfg: FeatureConfig) -> pd.DataFrame:
    """Compute windows for every labelled session and write ``windows.parquet``."""
    frames: list[pd.DataFrame] = []
    missing: list[str] = []
    for session in run.collected():
        path = run.labeled_path(session.execution_id)
        if not path.is_file():
            missing.append(session.execution_id)
            continue
        windows = session_windows(read_events(path).to_pandas(), session, cfg)
        if not windows.empty:
            frames.append(windows)
        log.info("features.session", execution_id=session.execution_id, windows=len(windows))
    if missing:
        raise GapHunterError(
            f"{len(missing)} session(s) are not labelled yet (e.g. {missing[0]}); "
            "run 'gaphunter label' first"
        )
    if not frames:
        raise GapHunterError("no events to build windows from")
    result = pd.concat(frames, ignore_index=True)
    result["window_start"] = pd.to_datetime(result["window_start"], utc=True)
    result["window_end"] = pd.to_datetime(result["window_end"], utc=True)
    result["first_malicious_ts"] = pd.to_datetime(result["first_malicious_ts"], utc=True)
    result["label"] = result["label"].astype(bool)
    feature_cols = feature_names(cfg)
    result[feature_cols] = result[feature_cols].astype("float32")
    result.to_parquet(run.windows_path, index=False)
    log.info(
        "features.done",
        windows=len(result),
        malicious=int(result["label"].sum()),
        features=len(feature_cols),
    )
    return result


def feature_columns(windows: pd.DataFrame) -> list[str]:
    return [c for c in windows.columns if c.startswith("f_")]


def summarize(windows: pd.DataFrame) -> dict[str, int]:
    return {
        "windows": len(windows),
        "baseline": int((windows["source"] == "baseline").sum()),
        "attack_session": int((windows["source"] == "attack").sum()),
        "malicious": int(windows["label"].sum()),
        "features": len(feature_columns(windows)),
    }


def iter_tokens(texts: Iterable[str], cfg: FeatureConfig) -> Iterable[str]:
    """Tokens as the feature stage sees them (handy when inspecting a detection)."""
    mask = frozenset(m.lower() for m in cfg.mask_tokens)
    for text in texts:
        yield from tokenize(text, mask)
