"""GapHunter command line.

Lab and collection commands::

    gaphunter lab check                      pre-flight checks
    gaphunter lab revert                     revert the VM to the clean snapshot
    gaphunter run init [--name N]            create a run directory (prints its path)
    gaphunter run status RUN                 list sessions and their state
    gaphunter session begin RUN ...          open a collection window (optionally revert first)
    gaphunter session end RUN                close the window, export + parse the logs
    gaphunter session collect RUN            retry collection for sessions that ended
    gaphunter session discard RUN ID         forget a session
    gaphunter parse FILE.evtx... --out P     offline .evtx -> Parquet

Analysis commands (all take the run directory)::

    gaphunter baseline RUN --hours N         scripted benign activity, collected in slices
    gaphunter label RUN                      ground-truth labels (window AND lineage)
    gaphunter features RUN                   windows.parquet
    gaphunter rules RUN                      Hayabusa -> alerts.parquet
    gaphunter train RUN                      ML detectors -> scores.parquet
    gaphunter evaluate RUN                   metrics -> RUN/eval
    gaphunter report RUN [-o DIR]            Navigator layers, figures, LaTeX, CSV
    gaphunter demo                           synthetic run to try the pipeline without a lab

Exit codes: 0 ok, 1 error, 3 ``session begin`` skipped because that session is already
collected (lets a loop over a plan be re-run safely after a crash).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

import typer

from gaphunter import __version__
from gaphunter import log as gh_log
from gaphunter.config import Config, load_config, load_credentials
from gaphunter.errors import GapHunterError, RunStateError
from gaphunter.rundir import RunDir, Session, SessionKind, make_execution_id

EXIT_ALREADY_COLLECTED = 3

app = typer.Typer(
    name="gaphunter",
    help="Measure detection coverage gaps: Sigma rules vs. ML anomaly detection.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,
)
lab_app = typer.Typer(help="Lab VM checks and snapshot control.", no_args_is_help=True)
run_app = typer.Typer(help="Run directories.", no_args_is_help=True)
session_app = typer.Typer(help="Collection windows on the VM.", no_args_is_help=True)
app.add_typer(lab_app, name="lab")
app.add_typer(run_app, name="run")
app.add_typer(session_app, name="session")

logger = gh_log.get_logger("gaphunter.cli")


@dataclass
class AppState:
    config: Config
    env_file: Path


def _state(ctx: typer.Context) -> AppState:
    state = ctx.obj
    assert isinstance(state, AppState)
    return state


def _fail(exc: GapHunterError) -> typer.Exit:
    logger.error("failed", error=str(exc), kind=type(exc).__name__)
    return typer.Exit(code=1)


def _remote(state: AppState) -> Any:
    from gaphunter.remote import SshRemote

    creds = load_credentials(state.config.ssh, env_file=state.env_file)
    return SshRemote(state.config.ssh, creds)


def _hypervisor(state: AppState) -> Any:
    from gaphunter.lab import LibvirtHypervisor

    return LibvirtHypervisor(state.config.lab)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"gaphunter {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    config: Annotated[Path | None, typer.Option("--config", "-c", help="YAML config file.")] = None,
    env_file: Annotated[Path, typer.Option(help="File with SSH user / key path.")] = Path(".env"),
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging.")] = False,
    json_logs: Annotated[bool, typer.Option(help="Log as JSON lines.")] = False,
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    gh_log.configure(verbose=verbose, json_logs=json_logs)
    try:
        ctx.obj = AppState(config=load_config(config), env_file=env_file)
    except GapHunterError as exc:
        raise _fail(exc) from exc


# -- lab -----------------------------------------------------------------------------


@lab_app.command("check")
def lab_check(ctx: typer.Context) -> None:
    """Verify snapshot, network isolation, SSH, Sysmon and log channels."""
    from gaphunter.lab import check_lab

    state = _state(ctx)
    try:
        hv = _hypervisor(state)
        try:
            results = check_lab(hv, _remote(state), state.config)
        finally:
            hv.close()
    except GapHunterError as exc:
        raise _fail(exc) from exc
    failed = False
    for result in results:
        mark = "ok  " if result.ok else ("FAIL" if result.fatal else "warn")
        typer.echo(f"[{mark}] {result.name:<11} {result.detail}")
        failed = failed or (not result.ok and result.fatal)
    if failed:
        raise typer.Exit(code=1)


@lab_app.command("revert")
def lab_revert(ctx: typer.Context) -> None:
    """Revert the VM to the configured clean snapshot and wait until it answers."""
    from gaphunter.lab import revert_and_wait

    state = _state(ctx)
    try:
        hv = _hypervisor(state)
        try:
            waited = revert_and_wait(hv, _remote(state), state.config.lab)
        finally:
            hv.close()
    except GapHunterError as exc:
        raise _fail(exc) from exc
    typer.echo(f"reverted to {state.config.lab.snapshot!r}; ready after {waited:.0f}s")


# -- run -----------------------------------------------------------------------------


@run_app.command("init")
def run_init(
    ctx: typer.Context,
    name: Annotated[str | None, typer.Option(help="Suffix for the run id.")] = None,
) -> None:
    """Create a run directory and print its path on stdout."""
    try:
        run = RunDir.create(_state(ctx).config, name=name)
    except GapHunterError as exc:
        raise _fail(exc) from exc
    typer.echo(str(run.path))


@run_app.command("status")
def run_status(run_dir: Path) -> None:
    """List the sessions of a run."""
    try:
        run = RunDir.open(run_dir)
        sessions = run.sessions()
    except GapHunterError as exc:
        raise _fail(exc) from exc
    if not sessions:
        typer.echo("no sessions yet")
        return
    for s in sessions:
        events = "-" if s.n_events is None else str(s.n_events)
        typer.echo(
            f"{s.execution_id:<28} {s.kind:<8} {s.status:<9} "
            f"{s.start_utc:%Y-%m-%dT%H:%M:%SZ}  events={events}"
        )
    pending = [s.execution_id for s in sessions if s.status != "collected"]
    if pending:
        typer.echo(f"pending: {', '.join(pending)}")


# -- session -------------------------------------------------------------------------


@session_app.command("begin")
def session_begin(
    ctx: typer.Context,
    run_dir: Path,
    kind: Annotated[str, typer.Option(help="'attack' or 'baseline'.")] = "attack",
    technique: Annotated[
        str | None, typer.Option(help="ATT&CK technique id, e.g. T1059.001.")
    ] = None,
    test: Annotated[int | None, typer.Option(help="Atomic test number.")] = None,
    test_guid: Annotated[str | None, typer.Option(help="Atomic test GUID.")] = None,
    rep: Annotated[int | None, typer.Option(help="Repetition number (1-based).")] = None,
    name: Annotated[str | None, typer.Option(help="Name for a baseline session.")] = None,
    revert: Annotated[
        bool, typer.Option("--revert/--no-revert", help="Revert to the clean snapshot first.")
    ] = False,
    force: Annotated[
        bool, typer.Option(help="Redo a collected session / ignore pending sessions.")
    ] = False,
) -> None:
    """Open a collection window: optionally revert the VM, then record the start time."""
    from gaphunter.lab import guest_info, guest_utc_now, revert_and_wait

    state = _state(ctx)
    try:
        if kind not in ("attack", "baseline"):
            raise RunStateError("--kind must be 'attack' or 'baseline'")
        session_kind: SessionKind = "attack" if kind == "attack" else "baseline"
        run = RunDir.open(run_dir)
        execution_id = make_execution_id(
            session_kind, technique_id=technique, test_number=test, repetition=rep, name=name
        )
        existing = run.get(execution_id)
        if existing is not None and existing.status == "collected" and not force:
            typer.echo(f"{execution_id}: already collected, skipping")
            raise typer.Exit(code=EXIT_ALREADY_COLLECTED)
        others = [s for s in run.pending() if s.execution_id != execution_id]
        if others and not force:
            ids = ", ".join(s.execution_id for s in others)
            raise RunStateError(
                f"uncollected session(s): {ids}. Finish them with 'session end' / "
                "'session collect', discard them, or pass --force. "
                "(A revert would destroy their logs.)"
            )
        if existing is not None:
            run.remove(execution_id)

        remote = _remote(state)
        if revert:
            hv = _hypervisor(state)
            try:
                revert_and_wait(hv, remote, state.config.lab)
            finally:
                hv.close()
        if not run.manifest().get("guest"):
            run.update_guest_info(guest_info(remote))

        start, control_pid = guest_utc_now(remote)
        session = Session(
            execution_id=execution_id,
            kind=session_kind,
            technique_id=technique if session_kind == "attack" else None,
            test_number=test if session_kind == "attack" else None,
            test_guid=test_guid,
            repetition=rep,
            start_utc=start,
            snapshot=state.config.lab.snapshot,
            reverted=revert,
            control_pids=[control_pid] if control_pid is not None else [],
        )
        run.upsert(session)
    except GapHunterError as exc:
        raise _fail(exc) from exc
    logger.info("session.begin", execution_id=execution_id, start_utc=start.isoformat())
    typer.echo(execution_id)


def _collect(state: AppState, run: RunDir, session: Session, remote: Any) -> Session:
    from gaphunter.collector import collect_session

    count = collect_session(remote, run, session, state.config.collector)
    done = session.model_copy(update={"status": "collected", "n_events": count})
    run.upsert(done)
    return done


@session_app.command("end")
def session_end(
    ctx: typer.Context,
    run_dir: Path,
    exit_code: Annotated[
        int | None, typer.Option(help="Exit status of what ran in the window.")
    ] = None,
    root_pid: Annotated[
        int | None,
        typer.Option(help="PID of the root process of the activity (used for lineage labels)."),
    ] = None,
    notes: Annotated[
        str | None, typer.Option(help="Free-text note stored with the session.")
    ] = None,
) -> None:
    """Close the open window, then export, copy and parse its logs."""
    from gaphunter.lab import guest_utc_now

    state = _state(ctx)
    try:
        run = RunDir.open(run_dir)
        open_sessions = [s for s in run.sessions() if s.status == "open"]
        if not open_sessions:
            raise RunStateError("no open session; use 'session begin' first")
        if len(open_sessions) > 1:
            ids = ", ".join(s.execution_id for s in open_sessions)
            raise RunStateError(f"more than one open session ({ids}); discard the stale ones")
        remote = _remote(state)
        end, control_pid = guest_utc_now(remote)
        current = open_sessions[0]
        pids = [*current.control_pids, *([control_pid] if control_pid is not None else [])]
        ended = current.model_copy(
            update={
                "end_utc": end,
                "status": "ended",
                "exit_code": exit_code,
                "executor_root_pid": root_pid,
                "notes": notes,
                "control_pids": pids,
            }
        )
        run.upsert(ended)  # persisted before collecting, so a failed export can be retried
        done = _collect(state, run, ended, remote)
    except GapHunterError as exc:
        raise _fail(exc) from exc
    typer.echo(f"{done.execution_id}: {done.n_events} events")


@session_app.command("collect")
def session_collect(ctx: typer.Context, run_dir: Path) -> None:
    """Retry log collection for sessions that ended but were not collected."""
    state = _state(ctx)
    try:
        run = RunDir.open(run_dir)
        ended = [s for s in run.sessions() if s.status == "ended"]
        if not ended:
            typer.echo("nothing to collect")
            return
        remote = _remote(state)
        for session in ended:
            done = _collect(state, run, session, remote)
            typer.echo(f"{done.execution_id}: {done.n_events} events")
    except GapHunterError as exc:
        raise _fail(exc) from exc


@session_app.command("discard")
def session_discard(run_dir: Path, execution_id: str) -> None:
    """Remove a session and its files from the run."""
    try:
        run = RunDir.open(run_dir)
        if run.get(execution_id) is None:
            raise RunStateError(f"no such session: {execution_id}")
        run.remove(execution_id)
    except GapHunterError as exc:
        raise _fail(exc) from exc
    typer.echo(f"discarded {execution_id}")


# -- analysis pipeline ---------------------------------------------------------------


@app.command("baseline")
def baseline_cmd(
    ctx: typer.Context,
    run_dir: Path,
    hours: Annotated[float, typer.Option(help="Hours of benign activity to collect.")] = 4.0,
    revert: Annotated[
        bool, typer.Option("--revert/--no-revert", help="Revert to the clean snapshot first.")
    ] = False,
) -> None:
    """Generate scripted benign activity on the VM and collect it in slices (resumable)."""
    from gaphunter.baseline import run_baseline
    from gaphunter.lab import guest_info, revert_and_wait

    state = _state(ctx)
    try:
        run = RunDir.open(run_dir)
        pending = [s.execution_id for s in run.pending() if s.kind != "baseline"]
        if pending:
            raise RunStateError(f"uncollected session(s): {', '.join(pending)}; finish them first")
        remote = _remote(state)
        if revert:
            hv = _hypervisor(state)
            try:
                revert_and_wait(hv, remote, state.config.lab)
            finally:
                hv.close()
        if not run.manifest().get("guest"):
            run.update_guest_info(guest_info(remote))
        created = run_baseline(remote, run, state.config, hours)
    except GapHunterError as exc:
        raise _fail(exc) from exc
    typer.echo(f"collected {len(created)} baseline slice(s)")


@app.command("label")
def label_cmd(
    ctx: typer.Context,
    run_dir: Path,
    force: Annotated[
        bool, typer.Option(help="Re-label sessions that are already labelled.")
    ] = False,
) -> None:
    """Label events: malicious = inside the session window AND in the root's lineage."""
    from gaphunter.labeler import label_run

    try:
        stats = label_run(RunDir.open(run_dir), _state(ctx).config.labeler, force=force)
    except GapHunterError as exc:
        raise _fail(exc) from exc
    malicious = sum(s.n_malicious for s in stats)
    noisy = [s.execution_id for s in stats if s.mode == "window_only"]
    empty = [s.execution_id for s in stats if s.mode == "no_lineage_events"]
    typer.echo(f"labelled {len(stats)} session(s), {malicious} malicious events")
    if noisy:
        typer.echo(f"window-only labels (no --root-pid): {', '.join(noisy)}")
    if empty:
        typer.echo(f"no telemetry from the root's lineage: {', '.join(empty)}")


@app.command("features")
def features_cmd(ctx: typer.Context, run_dir: Path) -> None:
    """Cut sessions into windows and compute features (writes windows.parquet)."""
    from gaphunter.features import build_windows, summarize

    try:
        windows = build_windows(RunDir.open(run_dir), _state(ctx).config.features)
    except GapHunterError as exc:
        raise _fail(exc) from exc
    typer.echo(", ".join(f"{k}={v}" for k, v in summarize(windows).items()))


@app.command("rules")
def rules_cmd(
    ctx: typer.Context,
    run_dir: Path,
    force: Annotated[bool, typer.Option(help="Re-run Hayabusa for every session.")] = False,
) -> None:
    """Run Hayabusa (Sigma rules) over each session's .evtx files (writes alerts.parquet)."""
    from gaphunter.detectors import run_rules

    try:
        alerts = run_rules(RunDir.open(run_dir), _state(ctx).config.rules, force=force)
    except GapHunterError as exc:
        raise _fail(exc) from exc
    typer.echo(f"{len(alerts)} alert(s)")


@app.command("train")
def train_cmd(ctx: typer.Context, run_dir: Path) -> None:
    """Fit the ML detectors on benign windows and score every window (scores.parquet)."""
    from gaphunter.detectors import train

    state = _state(ctx)
    try:
        scores = train(RunDir.open(run_dir), state.config.ml, state.config.seed)
    except GapHunterError as exc:
        raise _fail(exc) from exc
    models = scores[["config_id", "seed"]].drop_duplicates()
    typer.echo(f"trained {len(models)} model(s)")


@app.command("evaluate")
def evaluate_cmd(ctx: typer.Context, run_dir: Path) -> None:
    """Compute metrics, technique/tactic coverage and latency (writes <run>/eval)."""
    from gaphunter.evaluation import evaluate
    from gaphunter.reporter import detector_name

    try:
        result = evaluate(RunDir.open(run_dir), _state(ctx).config)
    except GapHunterError as exc:
        raise _fail(exc) from exc
    if result["summary"]["synthetic"]:
        typer.echo("SYNTHETIC DEMO DATA - NOT RESULTS")
    typer.echo(
        f"{'detector':<30} {'prec':>6} {'recall':>6} {'F1':>6} {'FPR':>6} {'techniques':>10}"
    )
    for _, row in result["detector_metrics"].iterrows():
        covered = f"{int(row['techniques_detected'])}/{int(row['techniques_with_telemetry'])}"
        typer.echo(
            f"{detector_name(str(row['detector'])):<30} {row['precision']:>6.3f} "
            f"{row['recall']:>6.3f} {row['f1']:>6.3f} {row['fpr']:>6.3f} {covered:>10}"
        )
    for key, value in result["summary"].get("gap_counts", {}).items():
        typer.echo(f"{key}: {value}")


@app.command("report")
def report_cmd(
    run_dir: Path,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output directory.")] = None,
) -> None:
    """Write Navigator layers, IEEE-style figures, LaTeX tables and CSVs."""
    from gaphunter.reporter import build_report

    try:
        run = RunDir.open(run_dir)
        target = output or (run.path / "report")
        written = build_report(run, target)
    except GapHunterError as exc:
        raise _fail(exc) from exc
    typer.echo(f"{len(written)} files -> {target}")


@app.command("demo")
def demo_cmd(
    ctx: typer.Context,
    name: Annotated[str, typer.Option(help="Suffix for the run id.")] = "demo",
    full: Annotated[
        bool, typer.Option("--full/--data-only", help="Also run label..report on it.")
    ] = True,
) -> None:
    """Create a run from SYNTHETIC data to try the analysis pipeline without a lab."""
    from gaphunter.detectors import run_rules, train
    from gaphunter.evaluation import evaluate
    from gaphunter.features import build_windows
    from gaphunter.labeler import label_run
    from gaphunter.reporter import build_report
    from gaphunter.synth import make_demo_run

    state = _state(ctx)
    try:
        run = make_demo_run(state.config, name=name)
        if full:
            label_run(run, state.config.labeler)
            build_windows(run, state.config.features)
            run_rules(run, state.config.rules)  # uses the fabricated alerts, not Hayabusa
            train(run, state.config.ml, state.config.seed)
            evaluate(run, state.config)
            build_report(run, run.path / "report")
    except GapHunterError as exc:
        raise _fail(exc) from exc
    typer.echo(str(run.path))


# -- offline parsing -----------------------------------------------------------------


@app.command("parse")
def parse_cmd(
    evtx: Annotated[list[Path], typer.Argument(help="One or more .evtx files.")],
    out: Annotated[Path, typer.Option("--out", "-o", help="Output Parquet file.")],
    execution_id: Annotated[
        str, typer.Option(help="Value for the execution_id column.")
    ] = "offline",
) -> None:
    """Parse .evtx files into the normalised events Parquet (no VM needed)."""
    from gaphunter.collector import dedupe_and_sort, parse_evtx, write_events

    try:
        rows: list[dict[str, Any]] = []
        for path in evtx:
            if not path.is_file():
                raise RunStateError(f"file not found: {path}")
            rows.extend(parse_evtx(path, execution_id=execution_id))
        count = write_events(dedupe_and_sort(rows), out)
    except GapHunterError as exc:
        raise _fail(exc) from exc
    typer.echo(f"{count} events -> {out}")


if __name__ == "__main__":  # pragma: no cover
    app()
