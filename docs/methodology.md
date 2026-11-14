# Methodology summary

Text to adapt for the Methodology and Experimental Setup sections. Replace the bracketed
values with those of your run (`manifest.json`, `eval/metrics.json`).

## Experimental setup

All experiments ran in an isolated KVM/libvirt lab on a single laptop ([CPU], 16 GB RAM,
no GPU). The target was a Windows 10 [build] virtual machine (4 GB RAM, 2 vCPU) attached
to a libvirt network without forwarding, so the guest could reach only the host. The
guest ran Sysmon [version] with the sysmon-modular configuration (hash [hash]), process
creation auditing with command lines, and PowerShell script block logging. Before every
technique execution the VM was reverted to the same running snapshot.

Adversary behaviour was emulated with existing Atomic Red Team tests; no new attack code
was written. Each of the [N] selected tests was executed [3] times. For each execution
GapHunter recorded the start and end time on the guest clock and the root process of the
emulation, then exported the Sysmon, Security and PowerShell Operational logs for that
window.

Benign training data was produced by a seeded script that performs ordinary administrative
and desktop activity over the same remote channel as the tests, collected in [K] slices
of 10 minutes ([H] hours in total).

## Ground truth

An event is labelled malicious if and only if (i) its timestamp lies within the execution
window and (ii) it was emitted by a process in the lineage rooted at the emulation's root
process, reconstructed from Sysmon process-creation events (events without a process GUID
are matched by PID within the process lifetime). All other events are benign. Executions
whose lineage produced no logged event are reported separately as having no telemetry and
are excluded from detection rates, since no log-based detector could observe them.

## Features

Logs are cut into non-overlapping [30] s windows. Each window is described by counts per
event ID, process-creation statistics (distinct images, parents and parent-child pairs,
integrity levels), command-line statistics (length, character entropy, share of special
characters and digits, presence of base64-like strings), a hashed bag of command-line and
script tokens ([256] buckets), hashed image and parent-child names, registry-path
categories, and file and network counts. The Sysmon rule-name field, the emulation
framework's own host process and tokens naming the framework are excluded to avoid label
leakage.

## Detectors

*Rule-based.* Hayabusa [version] with its Sigma rule set is run on the exported logs. A
window is flagged when it contains an alert of level [medium] or higher.

*ML-based.* Isolation Forest and a small fully connected autoencoder
(d-64-b-64-d, b in {8, 16}), optionally a One-Class SVM, are trained on benign windows
only. Counts are log-transformed and standardised and token buckets are TF-IDF weighted,
with all statistics fitted on benign training windows. The anomaly score is the negated
isolation score or the reconstruction error.

*Hybrid.* A window is flagged if either the rules or the ML detector flags it.

## Evaluation protocol

Benign sessions are split chronologically into training (60%), validation (20%) and test
(20%). Detection thresholds are the (1 - alpha) quantile of validation scores with
alpha = [0.01]. Hyper-parameters are selected leave-technique-out: the configuration used
to score technique t is the one with the highest average precision on validation
negatives and the malicious windows of all techniques other than t. Models are trained
with [3] random seeds and results are reported as mean and standard deviation.

We report window-level precision, recall, F1 and false-positive rate (on benign test
windows), ROC-AUC and PR-AUC (macro-averaged over held-out techniques), and detection
latency (end of the first flagged malicious window minus the first malicious event). An
execution counts as detected if at least one of its malicious windows is flagged, and a
technique as detected if at least [50]% of its executions are. Coverage per ATT&CK tactic
is the share of detected techniques among those with telemetry. The coverage gap is the
set of techniques missed by the rules; we report how many of them the ML detector
detects.

## Threats to validity

Single host and OS build; a short, scripted baseline that is less varied than real use;
coarse thresholds when few validation windows exist; label noise for activity that leaves
the process tree; residual artefacts of the emulation framework; rule alerts counted
regardless of whether the rule targets the executed technique; and telemetry bounded by
the Sysmon configuration. See the README for details and mitigations.
