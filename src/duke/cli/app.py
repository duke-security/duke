"""Command-line interface for Duke."""


from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from duke.detection import EventLoadError, detect_t1078, load_events
from duke.simulation import export_simulation, generate_t1078_simulation

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

if __name__ == "__main__":
    app()
