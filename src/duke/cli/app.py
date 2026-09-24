"""Command-line interface for Duke."""


from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from duke.detection import EventLoadError, detect_t1078, load_events
from duke.investigation import InvestigationResult, investigate_t1078
from duke.reporting import export_report, render_incident_report, report_t1078
from duke.response import ResponsePlan, plan_t1078_response
from duke.simulation import export_simulation, generate_t1078_simulation
from duke.telemetry import load_telemetry_artefact
from duke.validation import ValidationStatus, ValidationSuiteResult, validate_t1078

app = typer.Typer(
    name="duke",
    help="Learn Python through security detection, investigation, and response.",
    no_args_is_help=True,
)

console = Console()


def get_version() -> str:
    """Return the installed Duke version."""
    try:
        return package_version("duke-security")
    except PackageNotFoundError:
        return "unknown"


@app.callback()
def main() -> None:
    """Learn Python through modern security-engineering workflows."""



@app.command()
def version() -> None:
    """Display the installed Duke version."""
    console.print(f"Duke version {get_version()}")

@app.command()
def simulate(
    technique: Annotated[
        str,
        typer.Argument(
            help="MITRE ATT&CK technique to simulate, for example T1078.",
        ),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Path for the generated JSON artefact.",
        ),
    ] = Path("data/events/t1078-session-001.json"),
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Explicitly overwrite an existing output file.",
        ),
    ] = False,
) -> None:

    """Generate safe synthetic telemetry for an ATT&CK scenario."""
    normalized_technique = technique.upper()

    if normalized_technique != "T1078":
        console.print(
            f"[red]Unsupported technique:[/red] {technique}. "
            "Currently available: T1078",
        )
        raise typer.Exit(code=2)

    result = generate_t1078_simulation()

    try:
        saved_path = export_simulation(
            result,
            output,
            overwrite=force,
        )
    except FileExistsError as exc:
        console.print(f"[red]{exc}[/red]")
        console.print("Use --force to overwrite it explicitly.")
        raise typer.Exit(code=1) from exc

    console.print("[green]Simulation complete[/green]")
    console.print(f"Scenario: {result.scenario.name}")
    console.print(f"Technique: {result.scenario.attack_technique_id}")
    console.print(f"Entities generated: {len(result.entities)}")
    console.print(f"Events generated: {len(result.events)}")
    console.print(f"Saved: {saved_path}")

@app.command()
def detect(
    technique: Annotated[
        str,
        typer.Argument(
            help="MITRE ATT&CK technique to detect, for example T1078.",
        ),
    ],
    read_path: Annotated[
        Path,
        typer.Option(
            "--input",
            "-i",
            help="Path to the normalized events JSON artefact to detect against.",
        ),
    ] = Path("data/events/t1078-session-001.json"),
) -> None:
    """Run behaviour-based detection over a normalized telemetry artefact."""
    normalized_technique = technique.upper()

    if normalized_technique != "T1078":
        console.print(
            f"[red]Unsupported technique:[/red] {technique}. "
            "Currently available: T1078",
        )
        raise typer.Exit(code=2)

    try:
        events = load_events(read_path)
    except EventLoadError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    findings = detect_t1078(events)

    if not findings:
        console.print("[yellow]No findings[/yellow]")
        console.print(f"Events analysed: {len(events)}")
        return

    console.print("[green]Detection complete[/green]")
    console.print(f"Events analysed: {len(events)}")
    console.print(f"Findings: {len(findings)}")
    for finding in findings:
        console.print(f"- {finding.title}")
        console.print(f"    Detection: {finding.detection_name}")
        console.print(f"    Technique: {finding.technique_id}")
        console.print(f"    Severity: {finding.severity}")
        console.print(f"    Confidence: {finding.confidence}/100")
        console.print(f"    Supporting events: {len(finding.event_ids)}")
        console.print(f"    {finding.detection_details}")


def _print_investigation(result: InvestigationResult) -> None:
    """Print an evidence-led investigation summary."""
    console.print("[green]Investigation complete[/green]")
    console.print(f"Finding: {result.finding.title}")
    console.print(f"Technique: {result.finding.technique_id}")
    console.print(f"Severity: {result.finding.severity}")
    console.print(f"Confidence: {result.finding.confidence}/100")
    console.print(f"Involved entities: {len(result.involved_entities)}")
    console.print(f"Evidence items: {len(result.evidence)}")
    for evidence in result.evidence:
        console.print(f"  - {evidence.relationship}: {evidence.description}")
    console.print("Timeline:")
    for entry in result.timeline:
        console.print(
            f"  {entry.occurred_at.isoformat()}  {entry.summary}"
        )
    console.print("Confirmed facts:")
    for fact in result.confirmed_facts:
        console.print(f"  - {fact}")
    console.print("Analyst assessments:")
    for assessment in result.analyst_assessments:
        console.print(f"  - {assessment}")
    console.print("Unresolved questions:")
    for question in result.unresolved_questions:
        console.print(f"  - {question}")


@app.command()
def investigate(
    technique: Annotated[
        str,
        typer.Argument(
            help="MITRE ATT&CK technique to investigate, for example T1078.",
        ),
    ],
    read_path: Annotated[
        Path,
        typer.Option(
            "--input",
            "-i",
            help="Path to the normalized telemetry JSON artefact to investigate.",
        ),
    ] = Path("data/events/t1078-session-001.json"),
) -> None:
    """Investigate an existing finding against normalized telemetry."""
    normalized_technique = technique.upper()

    if normalized_technique != "T1078":
        console.print(
            f"[red]Unsupported technique:[/red] {technique}. "
            "Currently available: T1078",
        )
        raise typer.Exit(code=2)

    try:
        artefact = load_telemetry_artefact(read_path)
    except EventLoadError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    findings = detect_t1078(artefact.events)

    if not findings:
        console.print("[yellow]No findings to investigate[/yellow]")
        console.print(f"Events analysed: {len(artefact.events)}")
        return

    for finding in findings:
        result = investigate_t1078(artefact, finding)
        _print_investigation(result)


def _print_response_plan(plan: ResponsePlan) -> None:
    """Print a proposed, dry-run-only response plan."""
    console.print("[green]Response plan complete (DRY RUN — nothing executed)[/green]")
    console.print(
        f"Incident: {plan.incident.title} (status: {plan.incident.status}, "
        f"severity: {plan.incident.severity})"
    )
    console.print(f"Finding: {plan.finding.title}")
    console.print(
        f"Actions proposed: {len(plan.actions())} — all dry-run, all require approval"
    )

    for group in plan.groups:
        console.print("")
        console.print(f"[bold]{group.category.value.replace('_', ' ').title()}[/bold]")
        for action in group.actions:
            rollback = (
                "no rollback (irreversible)"
                if not action.supports_rollback
                else "rollback supported"
            )
            console.print(
                f"  - {action.name}  [risk: {action.risk}, approval: yes, "
                f"{rollback}]"
            )
            console.print(f"      Purpose: {action.purpose}")
            console.print(f"      Verify: {action.verification_guidance}")
            if action.rollback_guidance is not None:
                console.print(f"      Rollback: {action.rollback_guidance}")

    console.print("")
    console.print(
        "[yellow]No real account, session, permission, file, network, or "
        "security control was modified.[/yellow]"
    )


@app.command()
def respond(
    technique: Annotated[
        str,
        typer.Argument(
            help="MITRE ATT&CK technique to respond to, for example T1078.",
        ),
    ],
    read_path: Annotated[
        Path,
        typer.Option(
            "--input",
            "-i",
            help="Path to the normalized telemetry JSON artefact to respond to.",
        ),
    ] = Path("data/events/t1078-session-001.json"),
) -> None:
    """Propose a dry-run response plan from investigation of normalized telemetry."""
    normalized_technique = technique.upper()

    if normalized_technique != "T1078":
        console.print(
            f"[red]Unsupported technique:[/red] {technique}. "
            "Currently available: T1078",
        )
        raise typer.Exit(code=2)

    try:
        artefact = load_telemetry_artefact(read_path)
    except EventLoadError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    findings = detect_t1078(artefact.events)

    if not findings:
        console.print("[yellow]No findings to respond to[/yellow]")
        console.print(f"Events analysed: {len(artefact.events)}")
        return

    for finding in findings:
        result = investigate_t1078(artefact, finding)
        plan = plan_t1078_response(artefact, result)
        _print_response_plan(plan)


def _print_validation(suite: ValidationSuiteResult) -> None:
    """Print a detection-validation suite and its per-case results."""
    for case in suite.cases:
        mark = (
            "[green]PASS[/green]"
            if case.status is ValidationStatus.PASS
            else "[red]FAIL[/red]"
        )
        console.print(f"{mark} {case.name} — {case.actual}")
        console.print(f"      Expected: {case.expected}")
        console.print(f"      {case.explanation}")

    count = len(suite.cases)
    passed = sum(
        1 for case in suite.cases if case.status is ValidationStatus.PASS
    )
    if suite.all_passed:
        console.print(
            f"[green]Validation complete: {passed}/{count} cases passed[/green]"
        )
    else:
        console.print(
            f"[red]Validation failed: {passed}/{count} cases passed[/red]"
        )


@app.command()
def validate(
    technique: Annotated[
        str,
        typer.Argument(
            help="MITRE ATT&CK technique to validate, for example T1078.",
        ),
    ],
    read_path: Annotated[
        Path,
        typer.Option(
            "--input",
            "-i",
            help="Path to the normalized telemetry JSON artefact to validate.",
        ),
    ] = Path("data/events/t1078-session-001.json"),
) -> None:
    """Validate a technique's detection pipeline over a telemetry artefact."""
    normalized_technique = technique.upper()

    if normalized_technique != "T1078":
        console.print(
            f"[red]Unsupported technique:[/red] {technique}. "
            "Currently available: T1078",
        )
        raise typer.Exit(code=2)

    try:
        artefact = load_telemetry_artefact(read_path)
    except EventLoadError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    suite = validate_t1078(artefact)
    _print_validation(suite)

    if not suite.all_passed:
        raise typer.Exit(code=1)


@app.command()
def report(
    technique: Annotated[
        str,
        typer.Argument(
            help="MITRE ATT&CK technique to report on, for example T1078.",
        ),
    ],
    read_path: Annotated[
        Path,
        typer.Option(
            "--input",
            "-i",
            help="Path to the normalized telemetry JSON artefact to report on.",
        ),
    ] = Path("data/events/t1078-session-001.json"),
    output_path: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Path for the rendered incident report.",
        ),
    ] = Path("reports/t1078-incident-report.md"),
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Explicitly overwrite an existing report file.",
        ),
    ] = False,
) -> None:
    """Render a deterministic, advisory incident report from workflow data."""
    normalized_technique = technique.upper()

    if normalized_technique != "T1078":
        console.print(
            f"[red]Unsupported technique:[/red] {technique}. "
            "Currently available: T1078",
        )
        raise typer.Exit(code=2)

    try:
        artefact = load_telemetry_artefact(read_path)
    except EventLoadError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    findings = detect_t1078(artefact.events)

    if not findings:
        console.print("[yellow]No findings to report[/yellow]")
        console.print(f"Events analysed: {len(artefact.events)}")
        return  # exit 0; no output file is created

    # Run detection validation exactly once, before any report is built.
    suite = validate_t1078(artefact)
    if not suite.all_passed:
        console.print("[red]Validation failed[/red]")
        console.print("No report was generated.")
        raise typer.Exit(code=1)

    if len(findings) != 1:
        console.print(
            f"[red]Expected exactly one finding, got {len(findings)}[/red]"
        )
        console.print("No report was generated.")
        raise typer.Exit(code=1)

    finding = findings[0]
    result = investigate_t1078(artefact, finding)
    plan = plan_t1078_response(artefact, result)
    incident_report = report_t1078(artefact, finding, result, plan, suite)
    markdown = render_incident_report(incident_report)

    try:
        export_report(markdown, output_path, overwrite=force)
    except FileExistsError as exc:
        console.print(f"[red]{exc}[/red]")
        console.print("Use --force to overwrite it explicitly.")
        raise typer.Exit(code=1) from exc
    except OSError as exc:
        console.print(f"[red]Failed to write report: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    console.print("[green]Report complete[/green]")
    console.print(f"Report ID: {incident_report.report_id}")
    console.print(f"Validation: {len(suite.cases)}/{len(suite.cases)} cases passed")
    console.print(f"Saved: {output_path}")


if __name__ == "__main__":
    app()
