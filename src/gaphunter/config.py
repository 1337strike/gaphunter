"""YAML configuration (pydantic) plus secrets from the environment / .env.

Nothing secret lives in the YAML file. The SSH user name and private-key path are read
from environment variables whose *names* are configurable here.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from gaphunter.errors import ConfigError

DEFAULT_CONFIG_PATH = Path("configs/gaphunter.yaml")
DetectorName = Literal["iforest", "autoencoder", "ocsvm", "rarity"]
HybridName = Literal["iforest", "autoencoder", "ocsvm", "rarity", "ensemble"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LabConfig(_Model):
    libvirt_uri: str = "qemu:///system"
    domain: str = "gh-win11"
    snapshot: str = "clean"
    ready_timeout_s: int = Field(default=600, ge=10)
    ready_poll_s: float = Field(default=5.0, gt=0)
    # Seconds to let the guest settle after it first answers over SSH.
    settle_s: float = Field(default=15.0, ge=0)


class SshConfig(_Model):
    host: str = "10.66.66.10"
    port: int = Field(default=22, ge=1, le=65535)
    user_env: str = "GAPHUNTER_SSH_USER"
    key_env: str = "GAPHUNTER_SSH_KEY"
    known_hosts: Path = Path(".gaphunter/known_hosts")
    connect_timeout_s: int = Field(default=10, ge=1)
    command_timeout_s: int = Field(default=300, ge=1)


class CollectorConfig(_Model):
    remote_dir: str = r"C:\gaphunter\export"
    channels: dict[str, str] = Field(
        default_factory=lambda: {
            "sysmon": "Microsoft-Windows-Sysmon/Operational",
            "security": "Security",
            "powershell": "Microsoft-Windows-PowerShell/Operational",
        }
    )
    # Padding around the session window when exporting, to absorb log-write lag.
    pad_before_s: float = Field(default=2.0, ge=0)
    pad_after_s: float = Field(default=3.0, ge=0)
    # Wait this long after `session end` before exporting, so late events are flushed.
    flush_wait_s: float = Field(default=5.0, ge=0)

    @model_validator(mode="after")
    def _export_must_not_capture_itself(self) -> CollectorConfig:
        # The export command runs flush_wait_s after the window closes. If the padded
        # window reached past that point it would record the export's own processes.
        if self.pad_after_s > self.flush_wait_s:
            raise ValueError("collector.pad_after_s must not exceed collector.flush_wait_s")
        for alias in self.channels:
            if not alias.replace("_", "").isalnum():
                raise ValueError(f"channel alias {alias!r} must be alphanumeric")
        return self


class BaselineConfig(_Model):
    """Scripted benign activity used as ML training data."""

    slice_minutes: float = Field(default=10.0, gt=0)
    min_gap_s: float = Field(default=5.0, ge=0)
    max_gap_s: float = Field(default=45.0, ge=0)
    # Optional YAML file with extra activities: [{name: ..., script: ...}, ...]
    activities_file: Path | None = None
    replace_builtin: bool = False


class LabelerConfig(_Model):
    # Slack when matching PID-only events (Security, PowerShell) to a process lifetime.
    pid_slack_s: float = Field(default=2.0, ge=0)
    # What to do for an attack session without a usable lineage root:
    # "window" labels every in-window event (noisy), "skip" labels nothing.
    fallback: Literal["window", "skip"] = "window"


class FeatureConfig(_Model):
    window_s: float = Field(default=30.0, gt=0)
    token_buckets: int = Field(default=256, ge=8)
    name_buckets: int = Field(default=64, ge=8)
    # Tokens that identify the emulation framework itself; never used as features.
    mask_tokens: list[str] = Field(
        default_factory=lambda: [
            "invoke-atomictest",
            "invoke-atomicredteam",
            "atomicredteam",
            "atomic-red-team",
            "atomics",
            "atomictest",
            "gaphunter",
        ]
    )
    # Drop the events emitted by the lineage root process itself (the framework's own
    # PowerShell host), keeping everything its descendants do.
    exclude_root_process: bool = True


class RuleConfig(_Model):
    hayabusa_bin: str = "hayabusa"
    # Arguments after the binary. {evtx_dir} and {output} are substituted.
    # Hayabusa 4.x shown; for 3.x use:
    #   [json-timeline, -d, "{evtx_dir}", -o, "{output}", -L, -p, verbose, -w, -q, -U, --ISO-8601]
    args: list[str] = Field(
        default_factory=lambda: [
            "dfir-timeline",
            "-d",
            "{evtx_dir}",
            "-o",
            "{output}",
            "-t",
            "jsonl",
            "-p",
            "verbose",
            "-w",
            "-q",
            "--utc",
            "--iso-8601",
        ]
    )
    # A window counts as detected when it holds an alert at or above this level.
    min_level: Literal["informational", "low", "medium", "high", "critical"] = "medium"
    timeout_s: int = Field(default=600, ge=1)


class MlConfig(_Model):
    detectors: list[DetectorName] = ["iforest", "autoencoder", "rarity"]
    # Also score the average of the detectors' standardised scores as "ensemble".
    ensemble: bool = True
    seeds: list[int] = Field(default_factory=lambda: [1337, 1338, 1339], min_length=1)
    target_fpr: float = Field(default=0.01, gt=0, lt=1)
    # Benign baseline split into train / validation (thresholds) / test (FPR), by session.
    benign_split: tuple[float, float, float] = (0.6, 0.2, 0.2)
    split_order: Literal["chronological", "shuffled"] = "chronological"
    # Hyper-parameter grids. With more than one entry, the entry is chosen per held-out
    # technique using only the other techniques (leave-technique-out).
    iforest_grid: list[dict[str, Any]] = Field(
        default_factory=lambda: [
            {"n_estimators": 200, "max_samples": 256, "max_features": 1.0},
            {"n_estimators": 200, "max_samples": 256, "max_features": 0.5},
        ]
    )
    autoencoder_grid: list[dict[str, Any]] = Field(
        default_factory=lambda: [
            {"hidden": 64, "bottleneck": 8},
            {"hidden": 64, "bottleneck": 16},
        ]
    )
    ocsvm_grid: list[dict[str, Any]] = Field(
        default_factory=lambda: [{"nu": 0.01, "gamma": "scale"}, {"nu": 0.05, "gamma": "scale"}]
    )
    # Rarity: sum of the top_k most surprising hashed tokens / images / parent-child pairs.
    rarity_grid: list[dict[str, Any]] = Field(
        default_factory=lambda: [{"top_k": 10}, {"top_k": 30}]
    )
    ae_epochs: int = Field(default=200, ge=1)
    ae_batch_size: int = Field(default=64, ge=1)
    ae_lr: float = Field(default=1e-3, gt=0)
    ae_patience: int = Field(default=20, ge=1)
    ae_backend: Literal["auto", "torch", "numpy"] = "auto"
    ocsvm_max_train: int = Field(default=5000, ge=10)
    # The ML detector combined with the rules for the headline "hybrid" result.
    hybrid_ml: HybridName = "ensemble"

    @property
    def has_ensemble(self) -> bool:
        return self.ensemble and len(self.detectors) >= 2

    @model_validator(mode="after")
    def _check(self) -> MlConfig:
        if abs(sum(self.benign_split) - 1.0) > 1e-6 or min(self.benign_split) <= 0:
            raise ValueError("ml.benign_split must be three positive fractions summing to 1")
        if not self.detectors:
            raise ValueError("ml.detectors must not be empty")
        if self.hybrid_ml == "ensemble":
            if not self.has_ensemble:
                raise ValueError(
                    "ml.hybrid_ml is 'ensemble' but the ensemble is off or has fewer than "
                    "two detectors; pick one of ml.detectors instead"
                )
        elif self.hybrid_ml not in self.detectors:
            raise ValueError("ml.hybrid_ml must be 'ensemble' or one of ml.detectors")
        return self


class DetectConfig(_Model):
    """Live detection (``gaphunter detect``)."""

    top_features: int = Field(default=6, ge=1)
    top_commands: int = Field(default=5, ge=0)
    max_command_chars: int = Field(default=400, ge=40)


class EvalConfig(_Model):
    # A technique counts as detected when at least this share of its runs is detected.
    technique_min_rate: float = Field(default=0.5, gt=0, le=1)
    techniques_file: Path = Path("configs/techniques.yaml")


class Config(_Model):
    seed: int = 1337
    results_dir: Path = Path("results")
    lab: LabConfig = Field(default_factory=LabConfig)
    ssh: SshConfig = Field(default_factory=SshConfig)
    collector: CollectorConfig = Field(default_factory=CollectorConfig)
    baseline: BaselineConfig = Field(default_factory=BaselineConfig)
    labeler: LabelerConfig = Field(default_factory=LabelerConfig)
    features: FeatureConfig = Field(default_factory=FeatureConfig)
    rules: RuleConfig = Field(default_factory=RuleConfig)
    ml: MlConfig = Field(default_factory=MlConfig)
    evaluation: EvalConfig = Field(default_factory=EvalConfig)
    detect: DetectConfig = Field(default_factory=DetectConfig)


class SshCredentials(_Model):
    user: str
    key_path: Path


def load_config(path: Path | None = None) -> Config:
    """Load and validate the YAML config. A missing default file yields the defaults."""
    cfg_path = path or DEFAULT_CONFIG_PATH
    if not cfg_path.exists():
        if path is not None:
            raise ConfigError(f"config file not found: {cfg_path}")
        return Config()
    try:
        data: Any = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{cfg_path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{cfg_path}: top level must be a mapping")
    try:
        return Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"{cfg_path}: {exc}") from exc


def load_credentials(ssh: SshConfig, *, env_file: Path | None = Path(".env")) -> SshCredentials:
    """Read the SSH user and key path from the environment (optionally via .env)."""
    if env_file is not None and env_file.exists():
        load_dotenv(env_file, override=False)
    user = os.environ.get(ssh.user_env, "").strip()
    key = os.environ.get(ssh.key_env, "").strip()
    missing = [name for name, val in ((ssh.user_env, user), (ssh.key_env, key)) if not val]
    if missing:
        raise ConfigError(
            f"missing environment variable(s): {', '.join(missing)}. "
            "Copy .env.example to .env and fill it in."
        )
    key_path = Path(key).expanduser()
    if not key_path.is_file():
        raise ConfigError(f"SSH private key not found: {key_path} (from ${ssh.key_env})")
    return SshCredentials(user=user, key_path=key_path)


def dump_config(config: Config) -> str:
    """Serialise the effective config back to YAML (stored in every run directory)."""
    return yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False)
