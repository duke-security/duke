"""Tests for Duke's command-line interface."""

import json
from pathlib import Path

from typer.testing import CliRunner

from duke.cli.app import app
from duke.simulation import (
    export_simulation,
    generate_t1078_simulation,
    simulation_payload,
)

runner = CliRunner()


def test_help_displays_project_description() -> None:
    """The help command should explain Duke's purpose."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Learn Python through security detection" in result.stdout
    assert "version" in result.stdout


def test_version_displays_installed_version() -> None:
    """The version command should display Duke's installed version."""
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "Duke version 0.1.0" in result.stdout

def test_simulate_t1078_writes_json_artifact(tmp_path: Path) -> None:
    output_path = tmp_path / "t1078.json"

    result = runner.invoke(
        app,
        ["simulate", "T1078", "--output", str(output_path)],
    )

    assert result.exit_code == 0
    assert "Simulation complete" in result.stdout
    assert "Events generated: 8" in result.stdout
    assert output_path.exists()

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["scenario"]["attack_technique_id"] == "T1078"
    assert len(payload["events"]) == 8


def test_simulate_rejects_unsupported_technique(tmp_path: Path) -> None:
    output_path = tmp_path / "unsupported.json"

    result = runner.invoke(
        app,
        ["simulate", "T9999", "--output", str(output_path)],
    )

    assert result.exit_code == 2
    assert "Unsupported technique" in result.stdout
    assert not output_path.exists()


def test_simulate_requires_force_to_overwrite(tmp_path: Path) -> None:
    output_path = tmp_path / "t1078.json"

    first = runner.invoke(
        app,
        ["simulate", "T1078", "--output", str(output_path)],
    )
    second = runner.invoke(
        app,
        ["simulate", "T1078", "--output", str(output_path)],
    )
    forced = runner.invoke(
        app,
        [
            "simulate",
            "T1078",
            "--output",
            str(output_path),
            "--force",
        ],
    )

    assert first.exit_code == 0
    assert second.exit_code == 1
    assert "Output already exists" in second.stdout
    assert forced.exit_code == 0


def test_detect_t1078_reads_input_artifact(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")

    invocation = runner.invoke(
        app,
        ["detect", "T1078", "--input", str(input_path)],
    )

    assert invocation.exit_code == 0
    assert "Detection complete" in invocation.stdout
    assert "Findings: 1" in invocation.stdout
    assert "Confidence: 90/100" in invocation.stdout


def test_detect_rejects_unsupported_technique(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")

    invocation = runner.invoke(
        app,
        ["detect", "T9999", "--input", str(input_path)],
    )

    assert invocation.exit_code == 2
    assert "Unsupported technique" in invocation.stdout


def test_detect_missing_input_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    invocation = runner.invoke(
        app,
        ["detect", "T1078", "--input", str(missing)],
    )

    assert invocation.exit_code == 1
    assert "Input file not found or not a regular file" in invocation.stdout


def test_detect_malformed_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")

    invocation = runner.invoke(
        app,
        ["detect", "T1078", "--input", str(bad)],
    )

    assert invocation.exit_code == 1
    assert "Malformed JSON" in invocation.stdout


def test_detect_unsupported_schema_version(tmp_path: Path) -> None:
    unsupported = tmp_path / "v2.json"
    unsupported.write_text(
        json.dumps(
            {
                "schema_version": "2.0",
                "scenario": {},
                "entities": [],
                "events": [],
            }
        ),
        encoding="utf-8",
    )

    invocation = runner.invoke(
        app,
        ["detect", "T1078", "--input", str(unsupported)],
    )

    assert invocation.exit_code == 1
    assert "Unsupported schema version" in invocation.stdout


def test_detect_invalid_event_record(tmp_path: Path) -> None:
    payload = simulation_payload(generate_t1078_simulation())
    payload["events"][0].pop("occurred_at")
    invalid = tmp_path / "invalid-event.json"
    invalid.write_text(json.dumps(payload), encoding="utf-8")

    invocation = runner.invoke(
        app,
        ["detect", "T1078", "--input", str(invalid)],
    )

    assert invocation.exit_code == 1
    assert "Invalid SecurityEvent at index 0" in invocation.stdout
