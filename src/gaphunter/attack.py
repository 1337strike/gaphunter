"""ATT&CK technique metadata (name and tactics) used for reporting.

GapHunter does not bundle the ATT&CK knowledge base. List the techniques of your study in
``configs/techniques.yaml``; anything missing is reported under the tactic ``unmapped``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from gaphunter.errors import ConfigError

UNMAPPED = "unmapped"

# Display order and names of the enterprise tactics.
TACTIC_ORDER: tuple[str, ...] = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
    UNMAPPED,
)


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]


def tactic_label(tactic: str) -> str:
    return tactic.replace("-", " ").title().replace(" And ", " and ")


def load_techniques(path: Path | None) -> dict[str, Technique]:
    """Read ``{T1082: {name: ..., tactics: [discovery]}, ...}``. Missing file -> empty."""
    if path is None or not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a mapping of technique id to metadata")
    out: dict[str, Technique] = {}
    for key, meta in data.items():
        if not isinstance(meta, dict):
            raise ConfigError(f"{path}: entry {key!r} must be a mapping")
        tactics = meta.get("tactics") or [UNMAPPED]
        if isinstance(tactics, str):
            tactics = [tactics]
        normalised = tuple(str(t).strip().lower().replace(" ", "-") for t in tactics)
        unknown = [t for t in normalised if t not in TACTIC_ORDER]
        if unknown:
            raise ConfigError(f"{path}: {key}: unknown tactic(s) {unknown}")
        out[str(key).upper()] = Technique(str(key).upper(), str(meta.get("name", key)), normalised)
    return out


def describe(technique_id: str, known: dict[str, Technique]) -> Technique:
    """Metadata for a technique, falling back to its parent, then to 'unmapped'."""
    tid = technique_id.upper()
    if tid in known:
        return known[tid]
    parent = tid.split(".")[0]
    if parent in known:
        base = known[parent]
        return Technique(tid, base.name, base.tactics)
    return Technique(tid, tid, (UNMAPPED,))
