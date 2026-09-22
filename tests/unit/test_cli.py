"""Tests for Duke's command-line interface."""

import json
from pathlib import Path

from typer.testing import CliRunner

from duke.cli.app import app

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
