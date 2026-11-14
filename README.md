# GapHunter

Research tooling for measuring **detection coverage gaps**: which activity recorded in
Windows telemetry (Sysmon, Security, PowerShell logs) is missed by rule-based detection
(Sigma rules via Hayabusa), and how much of that gap ML-based anomaly detection closes.

GapHunter is the measurement side of the experiment. It controls a lab VM's snapshot,
collects and normalises the logs for a time window, labels them, extracts features, runs
the detectors and evaluates them. **It does not contain or execute attack code.**
Adversary emulation is done by you, inside your own lab, with an existing public
framework; GapHunter only needs to know *when* each test ran and from which process.

| Stage | Command | Output |
|-------|---------|--------|
| Lab control | `lab check`, `lab revert` | clean, isolated VM |
| Collection | `session begin` / `session end`, `baseline` | `.evtx` + `events/*.parquet` |
| Labels | `label` | `labeled/*.parquet` |
| Features | `features` | `windows.parquet` |
| Rule detector | `rules` (Hayabusa + Sigma) | `alerts.parquet` |
| ML detectors | `train` (Isolation Forest, autoencoder, optional One-Class SVM) | `scores.parquet` |
| Evaluation | `evaluate` | `eval/*.csv`, `eval/metrics.json` |
| Reporting | `report` | Navigator layers, PDF figures, LaTeX tables, CSV |

## Try it without a lab

```bash
just setup
just demo          # builds a run from SYNTHETIC data and runs label -> report on it
```

The demo data is invented (see `src/gaphunter/synth.py`); every file produced from it is
stamped "SYNTHETIC DEMO DATA - NOT RESULTS". It exists so you can see the pipeline and the
report formats before the lab is ready.

## Ethical use

- Use GapHunter only against machines you own or are explicitly authorised to test.
- Keep the lab isolated. `gaphunter lab check` refuses a VM whose libvirt network forwards
  traffic; do not work around that check.
- GapHunter ships no exploits, payloads, malware or evasion techniques, and contributions
  that add any will not be accepted. Its purpose is to improve detection.
- Logs from a real environment contain personal data (user names, command lines, paths).
  Only publish datasets generated in a lab with synthetic accounts.
- If your results reveal a blind spot in a public rule set, report it upstream so the
  rule can be fixed.

## Requirements

Host (developed for Arch Linux, 16 GB RAM, no GPU):

```bash
sudo pacman -S libvirt qemu-desktop virt-manager dnsmasq openssh just uv
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt "$USER"    # log out and back in
```

Python 3.11 or newer. `libvirt-python` builds against the system libvirt, which is why it
is an optional extra (`lab`): parsing and analysis work without it.

```bash
just setup          # uv venv + pip install -e ".[lab,dev]"
just test           # unit tests, no VM needed
```

## Lab setup

### 1. Isolated network

`lab/gaphunter-isolated.xml` defines a libvirt network with **no `<forward>` element**, so
the guest can reach the host bridge address and nothing else.

```bash
just net-up
virsh -c qemu:///system net-list --all
```

Edit the `<host mac=...>` line to your VM's MAC (`virsh domiflist gh-win10`) so it always
receives `10.66.66.10`.

### 2. Windows 10 VM

Create a Windows 10 evaluation VM named `gh-win10` (4 GB RAM, 2 vCPU, qcow2 disk). During
the build you can attach it to libvirt's default NAT network to install software; move it
to `gaphunter-isolated` before taking the snapshot.

In an elevated PowerShell inside the guest:

**OpenSSH Server with key authentication**

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic
Start-Service sshd
```

Create a dedicated key on the host and authorise it for the lab administrator:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/gaphunter_lab_ed25519 -C gaphunter-lab
```

```powershell
# paste the contents of gaphunter_lab_ed25519.pub into this file
notepad C:\ProgramData\ssh\administrators_authorized_keys
icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
```

**Sysmon with the sysmon-modular configuration**

Copy `Sysmon64.exe` (Sysinternals) and `sysmonconfig.xml` (olafhartong/sysmon-modular)
into the guest, then:

```powershell
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
```

GapHunter records the Sysmon version and config hash in every run manifest.

**Audit policy and PowerShell logging**

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456
wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:134217728
wevtutil sl Security /ms:268435456
```

**Emulation framework**

Install the adversary-emulation framework you use for the study by following its own
documentation (the paper uses Atomic Red Team with Invoke-AtomicRedTeam). GapHunter does
not install or drive it.

### 3. Clean snapshot

Switch the VM's NIC to `gaphunter-isolated`, reboot, confirm SSH works from the host, let
the guest idle for a few minutes, then snapshot it **while running** so reverts take
seconds instead of a full boot:

```bash
virsh -c qemu:///system snapshot-create-as gh-win10 clean "GapHunter clean state"
virsh -c qemu:///system snapshot-list gh-win10
```

If libvirt refuses an internal snapshot because of UEFI firmware, use a recent libvirt or
build the VM with BIOS firmware.

### 4. Configure GapHunter

```bash
cp .env.example .env        # set GAPHUNTER_SSH_USER and GAPHUNTER_SSH_KEY
$EDITOR configs/gaphunter.yaml
uv run gaphunter lab check
```

Expected output:

```
[ok  ] snapshot    'clean' found
[ok  ] isolation   no forwarding network
[ok  ] vm-running  running
[ok  ] ssh         PowerShell over SSH works
[ok  ] sysmon      Sysmon64 15.x running
[ok  ] channels    all configured log channels exist
```

## Collecting data

A **run** is a directory holding everything needed to reproduce a result. A **session**
is one collection window on the VM: either one emulation test (`--kind attack`) or a slice
of benign activity (`--kind baseline`).

```bash
RUN=$(uv run gaphunter run init --name pilot)

# open a window: revert to the clean snapshot, wait for the VM, record the start time
uv run gaphunter session begin "$RUN" --technique T1082 --test 1 --rep 1 --revert

#   ... run the test yourself inside the VM ...

# close the window: record the end time, export + copy + parse the logs
uv run gaphunter session end "$RUN" --exit-code 0

uv run gaphunter run status "$RUN"
```

Start and end times are read from the **guest clock**, because event timestamps come from
it and it jumps back on every snapshot revert.

Pass the PID of the process the test was started from to `session end --root-pid`. In a
PowerShell session that is `$PID`. Without it, labels fall back to "everything inside the
window", which is much noisier.

### Benign baseline

```bash
uv run gaphunter baseline "$RUN" --hours 4 --revert
```

Scripted, seeded, ordinary activity (listing processes, editing and archiving files,
reading settings, Notepad, a harmless scheduled task) is run over SSH and collected in
10-minute slices named `baseline-0001`, `baseline-0002`, ... Re-running the command
continues with the first slice that is not on disk. Add your own activities with
`baseline.activities_file` (a YAML list of `{name, script}`).

### Analysis

Install Hayabusa (a single binary from its GitHub releases) and make sure
`rules.hayabusa_bin` points to it. The default arguments are for Hayabusa 4.x; the
3.x form is in a comment in `configs/gaphunter.yaml`.

```bash
uv run gaphunter label "$RUN"
uv run gaphunter features "$RUN"
uv run gaphunter rules "$RUN"
uv run gaphunter train "$RUN"
uv run gaphunter evaluate "$RUN"
uv run gaphunter report "$RUN" -o results/paper
```

List your techniques in `configs/techniques.yaml` (name and tactics) so that tactic
coverage and table labels are right. `report` can be re-run on its own.

The autoencoder uses PyTorch when it is installed and an equivalent NumPy implementation
otherwise:

```bash
uv pip install torch --index-url https://download.pytorch.org/whl/cpu
```

### Resuming after a crash

State is written after every step (`state.json`), so nothing is redone needlessly:

- `session begin` on a session that is already collected prints a message and exits with
  code **3**, so a loop over your plan can simply be started again.
- If the export failed after `session end`, run `gaphunter session collect "$RUN"`.
- `session begin --revert` refuses to run while another session is uncollected, because
  the revert would destroy its logs.

### Parsing .evtx files without a VM

```bash
uv run gaphunter parse some.evtx other.evtx --out events.parquet
```

## Run directory

```
results/runs/<run_id>/
  manifest.json        seed, tool versions, VM domain + snapshot, Sysmon version/config hash
  config.yaml          effective configuration
  state.json           sessions and their status (resume point)
  executions.parquet   the same sessions as a table
  evtx/<execution_id>/{sysmon,security,powershell}.evtx
  events/<execution_id>.parquet
```

## Data schema

`events/<execution_id>.parquet`, one row per log record:

| Column | Type | Notes |
|--------|------|-------|
| `execution_id` | string | session the record was collected in |
| `host`, `channel`, `provider` | string | `channel` is `sysmon`, `security` or `powershell` |
| `event_id`, `record_id` | int | |
| `ts_utc` | timestamp[us, UTC] | from `System/TimeCreated` |
| `process_guid`, `pid`, `image`, `command_line` | | acting process |
| `parent_process_guid`, `parent_pid`, `parent_image`, `parent_command_line` | | |
| `user`, `integrity_level` | string | Security label SIDs are mapped to Low/Medium/High/System |
| `target_image`, `target_filename`, `target_object` | string | process, file / loaded image, registry |
| `dest_ip`, `dest_port` | | network connections |
| `script_block_text` | string | PowerShell 4104 / 4103 |
| `rule_name` | string | **audit only**, never a feature (sysmon-modular stores ATT&CK IDs here) |
| `raw` | string | all EventData fields as JSON |
| `label`, `technique_id`, `label_reason` | | filled by the labeler in phase 2 |

`executions.parquet`, one row per session: `execution_id`, `kind`, `technique_id`,
`test_number`, `test_guid`, `repetition`, `start_utc`, `end_utc`, `exit_code`,
`executor_root_pid`, `control_pids`, `snapshot`, `reverted`, `status`, `n_events`, `notes`.

`control_pids` are the PIDs of GapHunter's own remote PowerShell processes that fall inside
the window, so later stages can exclude the measurement tool's own footprint.

Further tables: `labeled/<execution_id>.parquet` (events with labels),
`windows.parquet` (one row per 30 s window: identity, label, `f_*` features),
`alerts.parquet` (normalised Hayabusa alerts), `splits.parquet` (train / val / test /
attack per window) and `scores.parquet` (`window_id`, `detector`, `config_id`, `seed`,
`score`).

## Method in brief

See `docs/methodology.md` for a write-up you can adapt for the paper.

- **Labels:** malicious = inside the session window AND in the process lineage of the
  root PID. Runs whose lineage left no events are reported as "no telemetry".
- **Features:** per 30 s window; event-ID counts, process and parent names, command-line
  statistics (length, entropy, special characters, base64), hashed command-line tokens,
  integrity levels, registry path categories, file and network counts.
- **ML:** trained on benign windows only; thresholds from held-out benign validation
  windows at a target false-positive rate (default 1%).
- **Leave-technique-out:** hyper-parameters used for a technique are chosen using only
  the other techniques.
- **Hybrid:** rule OR ML.

## Assumptions and threats to validity

- **Single host, single OS build.** Results describe this VM image and Sysmon config;
  the manifest records both so they can be reported.
- **Small, scripted baseline.** A few hours of scripted activity is far less varied than
  a real workstation, which favours anomaly detection. With few validation windows the
  1% threshold is coarse (with 100 windows it is simply the largest benign score).
- **Channel mismatch.** The baseline runs over SSH. If the tests are started some other
  way (for example from the desktop), the launch channel itself can look anomalous.
  Start the tests over SSH as well.
- **Label noise.** Lineage misses activity that escapes the process tree (services,
  scheduled tasks, WMI). Such events stay labelled benign, which lowers measured recall
  and shows up in the `in_session_benign_rate` column.
- **Framework artefacts.** Events of the root process itself and tokens naming the
  emulation framework are excluded from features; other artefacts of the framework
  (temporary paths, cleanup commands) may remain.
- **Rule attribution.** A rule alert anywhere in a malicious window counts as a
  detection even if the rule is not about that technique; `technique_match` in
  `rule_scores.parquet` gives the stricter view.
- **Guest clock.** Windows are defined on the guest clock. A clock step during a session
  would misplace the window.
- **Control-channel footprint.** GapHunter's own probe processes are stored in
  `control_pids` and excluded from labels, features and rule alerts.
- **Visibility is bounded by the Sysmon config.** Activity that sysmon-modular filters
  out is invisible to both detectors.
- **Precision depends on the class ratio**, which here is set by how much baseline was
  collected. Compare detectors at equal FPR rather than by precision alone.

## Development

```bash
just test     # pytest
just lint     # ruff
just types    # mypy --strict
```

## License

MIT
