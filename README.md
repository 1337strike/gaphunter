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
| ML detectors | `train` (Isolation Forest, autoencoder, rarity, ensemble; optional One-Class SVM) | `scores.parquet` |
| Evaluation | `evaluate` | `eval/*.csv`, `eval/metrics.json` |
| Reporting | `report` | Navigator layers, PDF figures, LaTeX tables, CSV, `report.html` |
| Deployment | `import-evtx`, `export-model`, `detect`, `explain` | model bundle, explained alerts (JSON lines) |

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
sudo pacman -S libvirt qemu-desktop virt-manager dnsmasq openssh just uv swtpm edk2-ovmf
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt "$USER"    # log out and back in
```

Python 3.11 or newer. `libvirt-python` builds against the system libvirt, which is why it
is an optional extra (`lab`): parsing and analysis work without it.

```bash
just setup          # uv sync with the lab and dev extras
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

Edit the `<host mac=...>` line to your VM's MAC (`virsh domiflist gh-win11`) so it always
receives `10.66.66.10`.

### 2. Windows 11 VM

Download the free 90-day **Windows 11 Enterprise evaluation** ISO (x64) from the Microsoft
Evaluation Center. Windows 11 needs UEFI firmware, a TPM and at least 64 GB of disk;
`--os-variant win11` makes virt-install add the firmware and an emulated TPM (`swtpm`).

```bash
virsh -c qemu:///system net-start default
virt-install -n gh-win11 --memory 6144 --vcpus 2 \
  --disk size=70,format=qcow2,bus=sata \
  --cdrom ~/Downloads/<the-iso-you-downloaded>.iso \
  --os-variant win11 --network network=default \
  --graphics spice --connect qemu:///system
```

Installation tips:

- **"Press any key to boot from CD or DVD" times out** before your keypress reaches the
  window (the window must have keyboard focus). Let the host press it instead:

  ```bash
  virsh -c qemu:///system reset gh-win11
  for i in $(seq 1 30); do virsh -c qemu:///system send-key gh-win11 KEY_SPACE; sleep 0.3; done
  ```

- **The mouse is stuck inside the VM window:** press left Ctrl + left Alt to release it.
- **Local account:** if setup shows "Let's connect you to a network", choose
  "I don't have internet"; it then offers a local account directly. With a network, choose
  "Sign-in options" then "Domain join instead". Name the account, for example, `labadmin`.
- **"network 'default' is not active":** `virsh -c qemu:///system net-start default` and
  `net-autostart default`.
- **ISO "may not be accessible by the hypervisor":** move it out of your home folder, for
  example to `/var/lib/libvirt/images/`.

The VM starts on libvirt's default NAT network so you can install software; it is moved to
`gaphunter-isolated` before the snapshot. 6 GB makes the installation bearable; 4 GB
(`virsh setmaxmem` / `setmem`) is enough afterwards.

The evaluation runs for 90 days from installation. Finish collecting within that time,
or rebuild the VM from a fresh ISO.

In an elevated PowerShell inside the guest:

**Host firewall (ufw users).** ufw blocks the VM's address request (DHCP) and its traffic
out of the default network; the VM then shows a `169.254.x.x` address. Allow both
networks' address requests, and forwarding only for the temporary default network:

```bash
BR=$(virsh -c qemu:///system net-info default | awk '/Bridge/{print $2}')
sudo ufw allow in on "$BR"
sudo ufw route allow in on "$BR"
sudo ufw route allow out on "$BR"
sudo ufw allow in on virbr-gh to any port 67 proto udp
sudo ufw reload
```

Restarting a libvirt network while a VM runs unplugs the VM; power it off and on with
`virsh shutdown` / `virsh start` afterwards.

**OpenSSH Server.** In the VM open an administrator PowerShell (right-click Start,
"Terminal (Admin)", or `Start-Process powershell -Verb RunAs`). Don't click inside an old
console window while a command runs: its title changes to "Select" and the command pauses
until you press Esc.

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic
Start-Service sshd
Set-NetFirewallRule -Name OpenSSH-Server-In-TCP -Profile Any
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
ipconfig
```

**Key login.** On the host, create a dedicated key (no passphrase, so GapHunter can run
unattended; it only opens this isolated lab VM) and authorise it for the lab
administrator. The last two commands ask for the Windows password:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/gaphunter_lab_ed25519 -N "" -C gaphunter-lab
scp ~/.ssh/gaphunter_lab_ed25519.pub labadmin@VM_IP:C:/ProgramData/ssh/administrators_authorized_keys
ssh labadmin@VM_IP "icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant Administrators:F /grant SYSTEM:F"
ssh -i ~/.ssh/gaphunter_lab_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes labadmin@VM_IP "echo key-login-works"
```

A warning that the connection "is not using a post-quantum key exchange algorithm" comes
from Windows' built-in SSH server and is harmless here.

**Sysmon, audit policy and PowerShell logging**

`lab/guest-setup.ps1` does all of it in one go: it installs standalone Sysinternals Sysmon
with the sysmon-modular configuration, turns on process-creation auditing with command
lines and PowerShell script block logging, and enlarges the event logs. Run it from the
host while the VM still has internet (replace `VM_IP` with the address `ipconfig` shows):

```bash
KEY=~/.ssh/gaphunter_lab_ed25519
scp -i $KEY lab/guest-setup.ps1 labadmin@VM_IP:C:/Users/labadmin/guest-setup.ps1
ssh -i $KEY labadmin@VM_IP "powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\labadmin\guest-setup.ps1"
```

It ends with `guest-setup: OK` and prints the Sysmon version, the sysmon-modular release
and the config hash, which GapHunter also records in every run manifest. The config
release is pinned for reproducibility; report it in the paper. It is safe to run again.

Windows 11 also ships a built-in Sysmon feature (off by default). GapHunter uses the
standalone release so the telemetry is the same on every Windows build; the two cannot run
side by side, and the script stops if the built-in one is enabled.

**Emulation framework**

Install the adversary-emulation framework you use for the study by following its own
documentation (the paper uses Atomic Red Team with Invoke-AtomicRedTeam). GapHunter does
not install or drive it.

### 3. Clean snapshot

Switch the VM's NIC to the isolated network, reboot, confirm SSH works from the host and
let the guest idle for a few minutes:

```bash
virt-xml gh-win11 --edit --network network=gaphunter-isolated -c qemu:///system
```

Then let GapHunter take the snapshot. It refuses if the VM is not isolated:

```bash
uv run gaphunter lab snapshot            # add --replace to recreate it later
```

#### UEFI and snapshots

A snapshot of the **running** VM makes every revert take seconds. For a UEFI guest
(every Windows 11 VM) libvirt only allows that when the firmware's NVRAM file is in
qcow2 format, and says so if it is not. Two ways forward:

1. **Offline snapshot (simplest).** Shut the VM down and snapshot it while off. GapHunter
   notices and boots the VM after every revert, which costs a minute or two per test.

   ```bash
   virsh -c qemu:///system shutdown gh-win11
   uv run gaphunter lab snapshot
   ```

2. **Live snapshot (faster).** Convert the NVRAM to qcow2 once, with the VM shut down.
   This needs libvirt 11.0 or newer and has not been tested by the authors.

   ```bash
   sudo qemu-img convert -f raw -O qcow2 \
     /var/lib/libvirt/qemu/nvram/gh-win11_VARS.fd \
     /var/lib/libvirt/qemu/nvram/gh-win11_VARS.qcow2
   virsh -c qemu:///system edit gh-win11
   #   inside <os>, replace the <nvram ...> element with:
   #   <nvram format='qcow2'>/var/lib/libvirt/qemu/nvram/gh-win11_VARS.qcow2</nvram>
   virsh -c qemu:///system start gh-win11
   uv run gaphunter lab snapshot
   ```

`gaphunter lab check` reports which kind you have (`snapshot-kind`). The emulated TPM's
state is not part of a snapshot; that does not matter for these experiments.

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
[ok  ] snapshot-kind live (reverts take seconds)
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

#   ... in another terminal: ssh into the VM, run the test, exit ...

# close the window: record the end time, export + copy + parse the logs, find the root
uv run gaphunter session end "$RUN" --exit-code 0

uv run gaphunter run status "$RUN"
```

Start and end times are read from the **guest clock**, because event timestamps come from
it and it jumps back on every snapshot revert.

Run the test from a fresh SSH session (`ssh -i <key> labadmin@10.66.66.10 powershell`),
one per session. `session end` then finds the root process by itself: the interactive
shell that SSH started and that started other processes, or, if the shell was opened a
moment before the window, the only PowerShell outside the window whose children ran
inside it. It prints `root PID ... detected`. You can still pass `--root-pid` (in PowerShell, `$PID`)
to set it explicitly. If neither works, labels fall back to "everything inside the
window", which is much noisier.

If the root PID was missed or mistyped, `label` reports "no telemetry from the root's
lineage". Find the right one among the processes the session started, then relabel:

```bash
uv run gaphunter session processes "$RUN" T1082-1-r1
uv run gaphunter session set-root "$RUN" T1082-1-r1 <PID>
uv run gaphunter label "$RUN"
```

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

Install Hayabusa from its GitHub releases (tested with 4.4.0; the Linux build is
`hayabusa-<version>-lin-x64-gnu.zip`, which contains the binary and its Sigma rules):

```bash
mkdir -p ~/tools/hayabusa && cd ~/tools/hayabusa
curl -LO https://github.com/Yamato-Security/hayabusa/releases/download/v4.4.0/hayabusa-4.4.0-lin-x64-gnu.zip
unzip -o hayabusa-4.4.0-lin-x64-gnu.zip && chmod +x hayabusa-4.4.0-lin-x64-gnu
ln -sf hayabusa-4.4.0-lin-x64-gnu hayabusa
```

Point `rules.hayabusa_bin` in `configs/gaphunter.yaml` at `~/tools/hayabusa/hayabusa`
(absolute path; keep the binary next to its `rules` and `config` folders). The default
arguments are for Hayabusa 4.x; the 3.x form is in a comment in the config. The Hayabusa
version is recorded in the run manifest.

Only Hayabusa's bundled **Sigma** rules are loaded (`rules.rule_set: sigma`). Hayabusa's own
"(Sysmon Alert)" rules fire on every event that the Sysmon configuration has annotated, and
sysmon-modular annotates events with ATT&CK techniques, so including them would make the
Sysmon config itself the detector. `rules.ignore_rules` drops the Sigma rule for programs
started by sshd, which fires on GapHunter's SSH control channel in every session. Both
choices are in the saved config of each run; report them with the results.

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

### Guided runs

For the experiment itself, `guide` walks through all repetitions of one test:

```bash
uv run gaphunter guide "$RUN" --technique T1082 --test 1 --reps 3
```

For each repetition it reverts the VM and opens the window, shows the SSH command and the
one line to paste into the VM, waits for you to press Enter, then closes the window,
collects the logs, detects the root process and labels the events. Type `r` to redo a
repetition or `q` to stop; running the same command again continues where it stopped.
GapHunter never runs the test itself; the line it shows is `guide.test_command` in the
config.

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

## Using it on your own environment

The lab answers "which techniques do my rules miss, and does ML catch them?". The same
models can then watch real logs. Train on what is normal for *your* machines:

```bash
RUN=$(uv run gaphunter run init --name fleet)

# 1. Benign logs from a machine you trust to be clean (one host per import).
#    Export them on that machine, for example:
#    wevtutil epl Microsoft-Windows-Sysmon/Operational sysmon.evtx
uv run gaphunter import-evtx "$RUN" pc01/sysmon.evtx pc01/security.evtx pc01/powershell.evtx --name pc01
#    (add --same-host if the machine was renamed and its logs carry two host names)

# 2. Features and a deployable model
uv run gaphunter label "$RUN"
uv run gaphunter features "$RUN"
uv run gaphunter export-model "$RUN" -o models/workstation.joblib

# 3. Score new logs (add --rules to run Hayabusa on the same files)
uv run gaphunter detect new/sysmon.evtx new/security.evtx -m models/workstation.joblib -o alerts.jsonl
```

Each ML alert says why it fired:

```
[HIGH  ] 2026-11-14T02:13:30+00:00  PC01  score 14.2 > 3.86  (212 events)
    - highest command-line entropy: 5.66 (benign ~4.2)
    - processes started with High integrity: 10 (benign ~0)
    - program names: 3  e.g. tool-x.exe
    > C:\Users\u\AppData\Local\Temp\tool-x.exe --mode ...
```

Things to know before relying on it:

- **Train per machine role.** A model of developer workstations will flag a domain
  controller constantly. `detect` warns when more than a fifth of the windows alert,
  which almost always means the baseline does not match the logs.
- **False alerts scale with volume.** At the default 1% threshold, a day of 30 s windows
  (2,880) yields about 29 false ML alerts per host. Lower `ml.target_fpr` and collect a
  longer baseline before using it for alerting; with few validation windows the threshold
  cannot be set finer than one over their number.
- **Batch, not streaming.** `detect` reads whole `.evtx` exports into memory; schedule it
  (cron, a pipeline step) on periodic exports. Very large files need a machine with
  enough RAM.
- **Your own Sigma rules:** add Hayabusa's rule options to `rules.args` in the config.
- **Model bundles are pickles.** Only load bundles you created; see `SECURITY.md`.
- Importing red-team exercise logs with `--kind attack --technique T... --root-pid N`
  lets you measure coverage on your own hosts with the same evaluation as the lab.

### Container

```bash
docker build -t gaphunter .
docker run --rm -v "$PWD:/work" gaphunter detect /work/new/sysmon.evtx -m /work/models/workstation.joblib
```

The image covers analysis and detection; lab control needs libvirt on the KVM host.

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
- **ML:** Isolation Forest, autoencoder and a rarity score, plus their ensemble; trained
  on benign windows only; thresholds from held-out benign validation windows at a target
  false-positive rate (default 1%).
- **Leave-technique-out:** hyper-parameters used for a technique are chosen using only
  the other techniques.
- **Hybrid:** rule OR ML (by default the ensemble; `ml.hybrid_ml` selects another).

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
- **Rule selection.** The rule detector is Sigma-only and one rule is ignored because it
  fires on the measurement harness (see "Analysis"). Results for "all bundled rules" can be
  produced with `rules.rule_set: all` and `rules --force`.
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

Commits on `main` are signed with the maintainer's key, so they show as Verified on
GitHub. Changes prepared elsewhere (for example by an assistant that cannot sign with
that key) are pushed to a branch and landed with:

```bash
just accept <branch>
```

which re-signs each commit with your key, fast-forwards `main`, pushes it and deletes the
branch. Your uncommitted local changes are stashed and restored around it.


```bash
just test     # pytest
just lint     # ruff
just types    # mypy --strict
```

## License

Apache-2.0. See `LICENSE` and `NOTICE`. Commercial use is permitted under its terms.
