"""ML anomaly detectors, trained on benign windows only. Everything runs on CPU.

Pipeline per (detector, hyper-parameter entry, seed):

1. split the benign baseline by session into train / validation / test;
2. fit the preprocessor (IDF weights, scaling) on benign-train only;
3. fit the detector on benign-train only;
4. score every window (higher = more anomalous) and store the scores.

No threshold and no hyper-parameter choice is made here; that happens in the evaluation,
where the choice for a technique can only use the other techniques.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import numpy as np
import pandas as pd

from gaphunter.config import MlConfig
from gaphunter.errors import GapHunterError
from gaphunter.features import feature_columns
from gaphunter.log import get_logger
from gaphunter.rundir import RunDir

log = get_logger(__name__)

FloatArray = np.ndarray[Any, np.dtype[np.float64]]


# -- preprocessing -------------------------------------------------------------------


class Preprocessor:
    """log1p + standardisation for counts/statistics, TF-IDF for hashed token buckets.

    Fitted on benign training windows only. A column that is constant in benign data keeps
    unit scale, so activity never seen in the baseline still shows up as a large value.
    """

    def __init__(self, columns: list[str]) -> None:
        self.columns = columns
        self._tok = [i for i, c in enumerate(columns) if c.startswith("f_tok_")]
        self._num = [i for i, c in enumerate(columns) if not c.startswith("f_tok_")]
        self._mean: FloatArray | None = None
        self._scale: FloatArray | None = None
        self._idf: FloatArray | None = None

    def _numeric(self, x: FloatArray) -> FloatArray:
        return np.log1p(np.clip(x[:, self._num], 0.0, None))

    def fit(self, x: FloatArray) -> Preprocessor:
        num = self._numeric(x)
        self._mean = num.mean(axis=0)
        std = num.std(axis=0)
        self._scale = np.where(std > 1e-9, std, 1.0)
        n_docs = x.shape[0]
        doc_freq = (x[:, self._tok] > 0).sum(axis=0)
        self._idf = np.log((1.0 + n_docs) / (1.0 + doc_freq)) + 1.0  # smoothed IDF
        return self

    @property
    def output_columns(self) -> list[str]:
        """Column names of ``transform`` output (numeric block, then token block)."""
        return [self.columns[i] for i in self._num] + [self.columns[i] for i in self._tok]

    def benign_mean(self) -> dict[str, float]:
        """Typical benign value per numeric feature, back in raw units."""
        if self._mean is None:
            raise GapHunterError("preprocessor used before fit")
        return {
            self.columns[i]: float(np.expm1(m)) for i, m in zip(self._num, self._mean, strict=True)
        }

    def idf(self) -> dict[str, float]:
        """IDF weight per token bucket (higher = rarer in benign data)."""
        if self._idf is None:
            raise GapHunterError("preprocessor used before fit")
        return {self.columns[i]: float(v) for i, v in zip(self._tok, self._idf, strict=True)}

    def transform(self, x: FloatArray) -> FloatArray:
        if self._mean is None or self._scale is None or self._idf is None:
            raise GapHunterError("preprocessor used before fit")
        num = np.clip((self._numeric(x) - self._mean) / self._scale, -10.0, 10.0)
        tfidf = np.log1p(x[:, self._tok]) * self._idf
        norms = np.linalg.norm(tfidf, axis=1, keepdims=True)
        tfidf = tfidf / np.where(norms > 0, norms, 1.0)
        return np.hstack([num, tfidf]).astype(np.float64)


# -- detectors -----------------------------------------------------------------------


class Detector(Protocol):
    def fit(self, x: FloatArray) -> None: ...
    def score(self, x: FloatArray) -> FloatArray: ...


class IsolationForestDetector:
    def __init__(self, params: dict[str, Any], seed: int) -> None:
        from sklearn.ensemble import IsolationForest

        self._params = dict(params)
        self._model_cls = IsolationForest
        self._seed = seed
        self._model: Any = None

    def fit(self, x: FloatArray) -> None:
        params = dict(self._params)
        if isinstance(params.get("max_samples"), int):
            params["max_samples"] = min(params["max_samples"], x.shape[0])
        self._model = self._model_cls(random_state=self._seed, n_jobs=1, **params).fit(x)

    def score(self, x: FloatArray) -> FloatArray:
        return np.asarray(-self._model.score_samples(x), dtype=np.float64)


class OneClassSvmDetector:
    def __init__(self, params: dict[str, Any], seed: int, max_train: int) -> None:
        from sklearn.svm import OneClassSVM

        self._model = OneClassSVM(kernel="rbf", **params)
        self._seed = seed
        self._max_train = max_train

    def fit(self, x: FloatArray) -> None:
        if x.shape[0] > self._max_train:
            rng = np.random.default_rng(self._seed)
            x = x[rng.choice(x.shape[0], self._max_train, replace=False)]
        self._model.fit(x)

    def score(self, x: FloatArray) -> FloatArray:
        return np.asarray(-self._model.decision_function(x), dtype=np.float64)


class RarityDetector:
    """How surprising are the strings in this window, given the benign baseline?

    Works on the raw hashed buckets (command-line tokens, image names, parent>child
    pairs). Each bucket gets a surprise ``-log((df + 1) / (n + 2))`` from the share of
    benign training windows it occurs in; a window's score is the sum of its ``top_k``
    most surprising buckets. Cheap, has no random state, and catches "never seen here
    before", which tree- and reconstruction-based models can miss.
    """

    uses_raw = True

    def __init__(self, params: dict[str, Any], columns: list[str]) -> None:
        self._top_k = int(params.get("top_k", 10))
        prefixes = ("f_tok_", "f_img_", "f_pair_")
        self._idx = [i for i, c in enumerate(columns) if c.startswith(prefixes)]
        self._surprise: FloatArray | None = None

    def fit(self, x: FloatArray) -> None:
        present = x[:, self._idx] > 0
        n = present.shape[0]
        self._surprise = -np.log((present.sum(axis=0) + 1.0) / (n + 2.0))

    def surprise(self, x: FloatArray) -> FloatArray:
        """Per-bucket surprise for each row (zero where the bucket is absent)."""
        if self._surprise is None:
            raise GapHunterError("rarity detector used before fit")
        return np.asarray((x[:, self._idx] > 0) * self._surprise, dtype=np.float64)

    def score(self, x: FloatArray) -> FloatArray:
        values = self.surprise(x)
        k = min(self._top_k, values.shape[1])
        top = np.partition(values, values.shape[1] - k, axis=1)[:, -k:]
        return np.asarray(top.sum(axis=1), dtype=np.float64)


@dataclass(frozen=True)
class AeSettings:
    hidden: int
    bottleneck: int
    epochs: int
    batch_size: int
    lr: float
    patience: int


class NumpyAutoencoder:
    """Small MLP autoencoder (d -> hidden -> bottleneck -> hidden -> d) in plain NumPy.

    Used when PyTorch is not installed. ReLU activations, MSE loss, Adam, early stopping
    on a held-back slice of the benign training data.
    """

    def __init__(self, settings: AeSettings, seed: int) -> None:
        self._s = settings
        self._seed = seed
        self._w: list[FloatArray] = []
        self._b: list[FloatArray] = []

    def _forward(self, x: FloatArray) -> tuple[list[FloatArray], FloatArray]:
        acts = [x]
        h = x
        last = len(self._w) - 1
        for i, (w, b) in enumerate(zip(self._w, self._b, strict=True)):
            h = h @ w + b
            if i != last:
                h = np.maximum(h, 0.0)
            acts.append(h)
        return acts, h

    def fit(self, x: FloatArray) -> None:
        rng = np.random.default_rng(self._seed)
        n, d = x.shape
        sizes = [d, self._s.hidden, self._s.bottleneck, self._s.hidden, d]
        self._w = [
            rng.normal(0.0, np.sqrt(2.0 / a), size=(a, b))
            for a, b in zip(sizes, sizes[1:], strict=False)
        ]
        self._b = [np.zeros(b) for b in sizes[1:]]
        order = rng.permutation(n)
        n_hold = max(1, n // 10) if n >= 20 else 0
        hold, train = x[order[:n_hold]], x[order[n_hold:]]
        m_w = [np.zeros_like(w) for w in self._w]
        v_w = [np.zeros_like(w) for w in self._w]
        m_b = [np.zeros_like(b) for b in self._b]
        v_b = [np.zeros_like(b) for b in self._b]
        beta1, beta2, eps, step = 0.9, 0.999, 1e-8, 0
        best, best_state, stale = np.inf, None, 0
        for _epoch in range(self._s.epochs):
            perm = rng.permutation(train.shape[0])
            for lo in range(0, len(perm), self._s.batch_size):
                batch = train[perm[lo : lo + self._s.batch_size]]
                acts, out = self._forward(batch)
                grad = 2.0 * (out - batch) / batch.size
                step += 1
                for i in range(len(self._w) - 1, -1, -1):
                    g_w = acts[i].T @ grad
                    g_b = grad.sum(axis=0)
                    if i > 0:
                        grad = (grad @ self._w[i].T) * (acts[i] > 0)
                    for param, g, m, v in (
                        (self._w, g_w, m_w, v_w),
                        (self._b, g_b, m_b, v_b),
                    ):
                        m[i] = beta1 * m[i] + (1 - beta1) * g
                        v[i] = beta2 * v[i] + (1 - beta2) * g * g
                        m_hat = m[i] / (1 - beta1**step)
                        v_hat = v[i] / (1 - beta2**step)
                        param[i] = param[i] - self._s.lr * m_hat / (np.sqrt(v_hat) + eps)
            monitor = hold if n_hold else train
            loss = float(np.mean((self._forward(monitor)[1] - monitor) ** 2))
            if loss < best - 1e-6:
                best, stale = loss, 0
                best_state = ([w.copy() for w in self._w], [b.copy() for b in self._b])
            else:
                stale += 1
                if stale >= self._s.patience:
                    break
        if best_state is not None:
            self._w, self._b = best_state

    def feature_errors(self, x: FloatArray) -> FloatArray:
        """Squared reconstruction error per feature (which inputs the model failed on)."""
        return np.asarray((self._forward(x)[1] - x) ** 2, dtype=np.float64)

    def score(self, x: FloatArray) -> FloatArray:
        return np.asarray(self.feature_errors(x).mean(axis=1), dtype=np.float64)


class TorchAutoencoder:
    """Same architecture and training recipe as NumpyAutoencoder, on PyTorch (CPU)."""

    def __init__(self, settings: AeSettings, seed: int) -> None:
        self._s = settings
        self._seed = seed
        self._model: Any = None

    def fit(self, x: FloatArray) -> None:
        import torch
        from torch import nn

        torch.manual_seed(self._seed)
        torch.set_num_threads(max(1, torch.get_num_threads()))
        n, d = x.shape
        s = self._s
        model = nn.Sequential(
            nn.Linear(d, s.hidden), nn.ReLU(),
            nn.Linear(s.hidden, s.bottleneck), nn.ReLU(),
            nn.Linear(s.bottleneck, s.hidden), nn.ReLU(),
            nn.Linear(s.hidden, d),
        )  # fmt: skip
        generator = torch.Generator().manual_seed(self._seed)
        order = torch.randperm(n, generator=generator)
        data = torch.tensor(x, dtype=torch.float32)
        n_hold = max(1, n // 10) if n >= 20 else 0
        hold, train = data[order[:n_hold]], data[order[n_hold:]]
        optimiser = torch.optim.Adam(model.parameters(), lr=s.lr)
        loss_fn = nn.MSELoss()
        best, best_state, stale = float("inf"), None, 0
        for _epoch in range(s.epochs):
            model.train()
            perm = torch.randperm(train.shape[0], generator=generator)
            for lo in range(0, len(perm), s.batch_size):
                batch = train[perm[lo : lo + s.batch_size]]
                optimiser.zero_grad()
                loss = loss_fn(model(batch), batch)
                loss.backward()
                optimiser.step()
            model.eval()
            with torch.no_grad():
                monitor = hold if n_hold else train
                value = float(loss_fn(model(monitor), monitor))
            if value < best - 1e-6:
                best, stale = value, 0
                best_state = {k: v.clone() for k, v in model.state_dict().items()}
            else:
                stale += 1
                if stale >= s.patience:
                    break
        if best_state is not None:
            model.load_state_dict(best_state)
        model.eval()
        self._model = model

    def feature_errors(self, x: FloatArray) -> FloatArray:
        import torch

        with torch.no_grad():
            data = torch.tensor(x, dtype=torch.float32)
            err = (self._model(data) - data) ** 2
        return np.asarray(err.numpy(), dtype=np.float64)

    def score(self, x: FloatArray) -> FloatArray:
        return np.asarray(self.feature_errors(x).mean(axis=1), dtype=np.float64)


def torch_available() -> bool:
    try:
        import torch  # noqa: F401
    except ImportError:
        return False
    return True


def autoencoder_backend(cfg: MlConfig) -> str:
    if cfg.ae_backend == "torch" and not torch_available():
        raise GapHunterError("ml.ae_backend is 'torch' but PyTorch is not installed")
    if cfg.ae_backend == "auto":
        return "torch" if torch_available() else "numpy"
    return cfg.ae_backend


def grid_for(cfg: MlConfig, detector: str) -> list[dict[str, Any]]:
    grid = {
        "iforest": cfg.iforest_grid,
        "autoencoder": cfg.autoencoder_grid,
        "ocsvm": cfg.ocsvm_grid,
        "rarity": cfg.rarity_grid,
    }[detector]
    if not grid:
        raise GapHunterError(f"empty hyper-parameter grid for {detector}")
    return grid


def make_detector(
    cfg: MlConfig, detector: str, params: dict[str, Any], seed: int, columns: list[str]
) -> Detector:
    if detector == "rarity":
        return RarityDetector(params, columns)
    if detector == "iforest":
        return IsolationForestDetector(params, seed)
    if detector == "ocsvm":
        return OneClassSvmDetector(params, seed, cfg.ocsvm_max_train)
    if detector == "autoencoder":
        settings = AeSettings(
            hidden=int(params.get("hidden", 64)),
            bottleneck=int(params.get("bottleneck", 8)),
            epochs=cfg.ae_epochs,
            batch_size=cfg.ae_batch_size,
            lr=cfg.ae_lr,
            patience=cfg.ae_patience,
        )
        if autoencoder_backend(cfg) == "torch":
            return TorchAutoencoder(settings, seed)
        return NumpyAutoencoder(settings, seed)
    raise GapHunterError(f"unknown detector {detector!r}")


def uses_raw(model: object) -> bool:
    """True for detectors that read the raw features instead of the preprocessed ones."""
    return bool(getattr(model, "uses_raw", False))


def robust_scale(benign_scores: FloatArray) -> tuple[float, float]:
    """Median and inter-quartile range of benign scores, for putting detectors on one scale."""
    q25, q50, q75 = np.quantile(benign_scores, [0.25, 0.5, 0.75])
    spread = float(q75 - q25)
    if spread <= 1e-12:
        spread = float(np.std(benign_scores)) or 1.0
    return float(q50), spread


# -- splits --------------------------------------------------------------------------


def split_windows(windows: pd.DataFrame, cfg: MlConfig, seed: int) -> pd.DataFrame:
    """Assign every window to train / val / test (baseline) or attack (attack sessions).

    Baseline sessions are split as whole units, so windows from one slice never land on
    both sides of a boundary.
    """
    baseline = windows[windows["source"] == "baseline"]
    order = baseline.groupby("execution_id")["window_start"].min().sort_values().index.to_list()
    if len(order) < 3:
        raise GapHunterError(
            f"need at least 3 baseline sessions to split train/val/test, found {len(order)}"
        )
    if cfg.split_order == "shuffled":
        np.random.default_rng(seed).shuffle(order)
    n = len(order)
    n_train = max(1, int(round(cfg.benign_split[0] * n)))
    n_val = max(1, int(round(cfg.benign_split[1] * n)))
    n_train = min(n_train, n - 2)
    n_val = min(n_val, n - n_train - 1)
    assignment = {eid: "train" for eid in order[:n_train]}
    assignment.update({eid: "val" for eid in order[n_train : n_train + n_val]})
    assignment.update({eid: "test" for eid in order[n_train + n_val :]})
    split = windows["execution_id"].map(assignment).where(windows["source"] == "baseline", "attack")
    return pd.DataFrame({"window_id": windows["window_id"], "split": split})


# -- training ------------------------------------------------------------------------


def train(run: RunDir, cfg: MlConfig, split_seed: int) -> pd.DataFrame:
    """Fit every detector/grid entry/seed on benign-train and score all windows."""
    if not run.windows_path.is_file():
        raise GapHunterError("windows.parquet not found; run 'gaphunter features' first")
    windows = pd.read_parquet(run.windows_path)
    columns = feature_columns(windows)
    splits = split_windows(windows, cfg, split_seed)
    splits.to_parquet(run.splits_path, index=False)
    x_all = windows[columns].to_numpy(dtype=np.float64)
    train_mask = (splits["split"] == "train").to_numpy()
    if train_mask.sum() < 10:
        raise GapHunterError(
            f"only {int(train_mask.sum())} benign training windows; collect more baseline"
        )
    prep = Preprocessor(columns).fit(x_all[train_mask])
    z_all = prep.transform(x_all)
    z_train = z_all[train_mask]

    frames: list[pd.DataFrame] = []
    first_config: dict[tuple[str, int], FloatArray] = {}
    for detector in cfg.detectors:
        for index, params in enumerate(grid_for(cfg, detector)):
            config_id = f"{detector}#{index}"
            for seed in cfg.seeds:
                model = make_detector(cfg, detector, params, seed, columns)
                raw = uses_raw(model)
                model.fit(x_all[train_mask] if raw else z_train)
                scores = model.score(x_all if raw else z_all)
                if index == 0:
                    first_config[(detector, seed)] = scores
                if not np.all(np.isfinite(scores)):
                    raise GapHunterError(f"{config_id} seed {seed} produced non-finite scores")
                frames.append(
                    pd.DataFrame(
                        {
                            "window_id": windows["window_id"].to_numpy(),
                            "detector": detector,
                            "config_id": config_id,
                            "seed": seed,
                            "score": scores,
                        }
                    )
                )
                log.info("train.fitted", config=config_id, seed=seed, params=params)
    if cfg.has_ensemble:
        # Average of robustly standardised scores (first grid entry of each detector).
        for seed in cfg.seeds:
            parts = []
            for detector in cfg.detectors:
                scores = first_config[(detector, seed)]
                loc, scale = robust_scale(scores[train_mask])
                parts.append((scores - loc) / scale)
            frames.append(
                pd.DataFrame(
                    {
                        "window_id": windows["window_id"].to_numpy(),
                        "detector": "ensemble",
                        "config_id": "ensemble#0",
                        "seed": seed,
                        "score": np.mean(parts, axis=0),
                    }
                )
            )
    result = pd.concat(frames, ignore_index=True)
    result.to_parquet(run.scores_path, index=False)
    log.info(
        "train.done",
        train_windows=int(train_mask.sum()),
        val_windows=int((splits["split"] == "val").sum()),
        test_windows=int((splits["split"] == "test").sum()),
        models=len(frames),
    )
    return result
