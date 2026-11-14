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

- `gaphunter lab snapshot`: takes the clean snapshot, refuses a VM that is not isolated,
  and explains libvirt's UEFI/NVRAM refusal. `lab check` reports whether the snapshot is
  live or offline.
- `lab/guest-setup.ps1`: one script for the guest's telemetry (Sysmon with sysmon-modular,
  process-creation auditing with command lines, PowerShell script block logging, log sizes),
  run from the host over SSH.
- `session processes` lists the processes a session started; `session set-root` corrects a
  missed or mistyped root PID so `label` can redo the labels.
- `--same-host` for `import-evtx` and `detect`, for a machine that logged under two names
  (Windows setup names it WIN-XXXX before it is renamed).

Changed
- The lab target is now Windows 11 Enterprise (the Windows 10 evaluation is no longer
  offered). Default domain name is `gh-win11`; `lab.ready_timeout_s` defaults to 600.
- Baseline activities no longer depend on Notepad, a Store app on Windows 11 that does not
  start reliably from a non-interactive session.
- License is now Apache-2.0 (was MIT).
- Default detectors are Isolation Forest, autoencoder and rarity; the headline hybrid is
  rules OR ensemble (`ml.hybrid_ml`). Set `ml.hybrid_ml: autoencoder` for the 0.1 behaviour.
- Feature set changed, so `windows.parquet` and scores from 0.1 must be rebuilt
  (`gaphunter features`, `gaphunter train`).

Fixed
- Hayabusa has no `--version` flag; its version is now read from the banner of `hayabusa help`
  (checked against the real 4.4.0 binary).
- Rule alerts from imported files with arbitrary names took the file name as their channel;
  Hayabusa's own channel abbreviation is now preferred.
- A run whose root process left no events is reported as "no telemetry" instead of having
  every in-window event labelled malicious.

## 0.1.0

Lab control, session collection, EVTX parsing, labelling, features, Hayabusa and ML
detectors, leave-technique-out evaluation, Navigator layers, figures and LaTeX tables.
