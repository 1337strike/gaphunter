# Changelog

## 0.2.0

Added
- `gaphunter detect`: score new `.evtx` files with a saved model, optionally together with
  Hayabusa, and write alerts as JSON lines. `--fail-on-alert` exits with code 2.
- Explanations on every ML alert: the features that deviate from the benign baseline, the
  strings behind hashed features, and the rarest command lines in the window.
  `gaphunter explain` does the same for any window of a run.
- `gaphunter export-model`: train a deployable model bundle (single detector or ensemble).
- `gaphunter import-evtx`: bring your own logs into a run, as benign baseline or as an
  attack session, so models are trained on your environment rather than only on the lab.
- Rarity detector (surprise of command-line words, program names and parent>child pairs)
  and a score ensemble; both are evaluated like every other detector.
- Process-tree and launch-context features (chain depth, fan-out, user-writable paths,
  script hosts, very long command lines).
- Self-contained `report.html`, Dockerfile, GitHub Actions CI, PyPI metadata.

Changed
- License is now Apache-2.0 (was MIT).
- Default detectors are Isolation Forest, autoencoder and rarity; the headline hybrid is
  rules OR ensemble (`ml.hybrid_ml`). Set `ml.hybrid_ml: autoencoder` for the 0.1 behaviour.
- Feature set changed, so `windows.parquet` and scores from 0.1 must be rebuilt
  (`gaphunter features`, `gaphunter train`).

Fixed
- A run whose root process left no events is reported as "no telemetry" instead of having
  every in-window event labelled malicious.

## 0.1.0

Lab control, session collection, EVTX parsing, labelling, features, Hayabusa and ML
detectors, leave-technique-out evaluation, Navigator layers, figures and LaTeX tables.
