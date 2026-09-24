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


def test_investigate_t1078_reads_input_artifact(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")

    invocation = runner.invoke(
        app,
        ["investigate", "T1078", "--input", str(input_path)],
    )

    assert invocation.exit_code == 0
    assert "Investigation complete" in invocation.stdout
    assert "Compromised identity used from unfamiliar device" in invocation.stdout
    assert "Confirmed facts:" in invocation.stdout
    assert "Analyst assessments:" in invocation.stdout
    assert "Unresolved questions:" in invocation.stdout


def test_investigate_no_findings_is_benign(tmp_path: Path) -> None:
    # A benign artefact: only the known-good baseline and routine access.
    result = generate_t1078_simulation()
    payload = simulation_payload(result)
    payload["events"] = payload["events"][:2]
    input_path = tmp_path / "benign.json"
    input_path.write_text(json.dumps(payload), encoding="utf-8")

    invocation = runner.invoke(
        app,
        ["investigate", "T1078", "--input", str(input_path)],
    )

    assert invocation.exit_code == 0
    assert "No findings to investigate" in invocation.stdout
    assert "Investigation complete" not in invocation.stdout


def test_investigate_rejects_unsupported_technique(tmp_path: Path) -> None:
    invocation = runner.invoke(
        app,
        ["investigate", "T9999", "--input", str(tmp_path / "x.json")],
    )

    assert invocation.exit_code == 2
    assert "Unsupported technique" in invocation.stdout


def test_investigate_missing_input_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    invocation = runner.invoke(
        app,
        ["investigate", "T1078", "--input", str(missing)],
    )

    assert invocation.exit_code == 1
    assert "Input file not found or not a regular file" in invocation.stdout


def test_investigate_invalid_artefact_exits_one(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")

    invocation = runner.invoke(
        app,
        ["investigate", "T1078", "--input", str(bad)],
    )

    assert invocation.exit_code == 1
    assert "Malformed JSON" in invocation.stdout


def test_respond_t1078_reads_input_artifact(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")

    invocation = runner.invoke(
        app,
        ["respond", "T1078", "--input", str(input_path)],
    )

    assert invocation.exit_code == 0
    assert "Response plan complete (DRY RUN" in invocation.stdout
    assert "Actions proposed: 9" in invocation.stdout
    assert "Containment" in invocation.stdout
    assert "disable-account" in invocation.stdout
    assert "nothing executed" in invocation.stdout
    assert "No real account" in invocation.stdout
    assert "modified" in invocation.stdout


def test_respond_no_findings_is_benign(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    payload = simulation_payload(result)
    payload["events"] = payload["events"][:2]
    input_path = tmp_path / "benign.json"
    input_path.write_text(json.dumps(payload), encoding="utf-8")

    invocation = runner.invoke(
        app,
        ["respond", "T1078", "--input", str(input_path)],
    )

    assert invocation.exit_code == 0
    assert "No findings to respond to" in invocation.stdout
    assert "Response plan complete" not in invocation.stdout


def test_respond_rejects_unsupported_technique(tmp_path: Path) -> None:
    invocation = runner.invoke(
        app,
        ["respond", "T9999", "--input", str(tmp_path / "x.json")],
    )

    assert invocation.exit_code == 2
    assert "Unsupported technique" in invocation.stdout


def test_respond_missing_input_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    invocation = runner.invoke(
        app,
        ["respond", "T1078", "--input", str(missing)],
    )

    assert invocation.exit_code == 1
    assert "Input file not found or not a regular file" in invocation.stdout


def test_respond_malformed_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")

    invocation = runner.invoke(
        app,
        ["respond", "T1078", "--input", str(bad)],
    )

    assert invocation.exit_code == 1
    assert "Malformed JSON" in invocation.stdout


def test_respond_unsupported_schema_version(tmp_path: Path) -> None:
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
        ["respond", "T1078", "--input", str(unsupported)],
    )

    assert invocation.exit_code == 1
    assert "Unsupported schema version" in invocation.stdout


def test_validate_t1078_reads_input_artifact(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")

    invocation = runner.invoke(
        app,
        ["validate", "T1078", "--input", str(input_path)],
    )

    assert invocation.exit_code == 0
    assert "Validation complete: 16/16 cases passed" in invocation.stdout
    assert "PASS suspicious-corpus-unmodified" in invocation.stdout


def test_validate_benign_artefact_produces_failed_suite(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    payload = simulation_payload(result)
    payload["events"] = payload["events"][:2]
    input_path = tmp_path / "benign.json"
    input_path.write_text(json.dumps(payload), encoding="utf-8")

    invocation = runner.invoke(
        app,
        ["validate", "T1078", "--input", str(input_path)],
    )

    assert invocation.exit_code == 1
    assert "Validation failed" in invocation.stdout


def test_validate_does_not_modify_input_file(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")
    before = input_path.read_bytes()

    invocation = runner.invoke(
        app,
        ["validate", "T1078", "--input", str(input_path)],
    )

    assert invocation.exit_code == 0
    assert input_path.read_bytes() == before


def test_validate_rejects_unsupported_technique(tmp_path: Path) -> None:
    invocation = runner.invoke(
        app,
        ["validate", "T9999", "--input", str(tmp_path / "x.json")],
    )

    assert invocation.exit_code == 2
    assert "Unsupported technique" in invocation.stdout


def test_validate_missing_input_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    invocation = runner.invoke(
        app,
        ["validate", "T1078", "--input", str(missing)],
    )

    assert invocation.exit_code == 1
    assert "Input file not found or not a regular file" in invocation.stdout


def test_validate_malformed_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")

    invocation = runner.invoke(
        app,
        ["validate", "T1078", "--input", str(bad)],
    )

    assert invocation.exit_code == 1
    assert "Malformed JSON" in invocation.stdout


def test_validate_unsupported_schema_version(tmp_path: Path) -> None:
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
        ["validate", "T1078", "--input", str(unsupported)],
    )

    assert invocation.exit_code == 1
    assert "Unsupported schema version" in invocation.stdout


def test_report_writes_output_file(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")
    output_path = tmp_path / "reports" / "incident.md"

    invocation = runner.invoke(
        app,
        [
            "report", "T1078",
            "--input", str(input_path),
            "--output", str(output_path),
        ],
    )

    assert invocation.exit_code == 0
    assert "Report complete" in invocation.stdout
    assert output_path.exists()
    body = output_path.read_text(encoding="utf-8")
    assert "# T1078 Incident Report" in body
    assert "## 10. Validation summary" in body


def test_report_benign_artefact_writes_nothing(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    payload = simulation_payload(result)
    payload["events"] = payload["events"][:2]  # baseline + routine only
    input_path = tmp_path / "benign.json"
    input_path.write_text(json.dumps(payload), encoding="utf-8")
    output_path = tmp_path / "incident.md"

    invocation = runner.invoke(
        app,
        [
            "report", "T1078",
            "--input", str(input_path),
            "--output", str(output_path),
        ],
    )

    assert invocation.exit_code == 0
    assert "No findings to report" in invocation.stdout
    assert not output_path.exists()


def test_report_refuses_existing_output_without_force(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")
    output_path = tmp_path / "incident.md"
    output_path.write_text("existing", encoding="utf-8")

    invocation = runner.invoke(
        app,
        [
            "report", "T1078",
            "--input", str(input_path),
            "--output", str(output_path),
        ],
    )

    assert invocation.exit_code == 1
    assert "Output already exists" in invocation.stdout
    assert output_path.read_text(encoding="utf-8") == "existing"


def test_report_force_overwrites_output(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")
    output_path = tmp_path / "incident.md"
    output_path.write_text("existing", encoding="utf-8")

    invocation = runner.invoke(
        app,
        [
            "report", "T1078",
            "--input", str(input_path),
            "--output", str(output_path),
            "--force",
        ],
    )

    assert invocation.exit_code == 0
    assert "# T1078 Incident Report" in output_path.read_text(encoding="utf-8")


def test_report_rejects_unsupported_technique(tmp_path: Path) -> None:
    invocation = runner.invoke(
        app,
        ["report", "T9999", "--input", str(tmp_path / "x.json")],
    )

    assert invocation.exit_code == 2
    assert "Unsupported technique" in invocation.stdout


def test_report_missing_input_file(tmp_path: Path) -> None:
    invocation = runner.invoke(
        app,
        [
            "report", "T1078",
            "--input", str(tmp_path / "missing.json"),
            "--output", str(tmp_path / "incident.md"),
        ],
    )

    assert invocation.exit_code == 1
    assert "Input file not found or not a regular file" in invocation.stdout
    assert not (tmp_path / "incident.md").exists()


def test_report_failed_validation_writes_nothing(tmp_path: Path, monkeypatch) -> None:
    from duke.validation import (
        ValidationCase,
        ValidationStatus,
        ValidationSuiteResult,
    )

    def failing(_artefact):
        return ValidationSuiteResult(
            technique_id="T1078",
            cases=(
                ValidationCase(
                    name="x",
                    expected="expected",
                    actual="actual",
                    status=ValidationStatus.FAIL,
                    explanation="why.",
                ),
            ),
        )

    monkeypatch.setattr("duke.cli.app.validate_t1078", failing)
    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")
    output_path = tmp_path / "incident.md"

    invocation = runner.invoke(
        app,
        [
            "report", "T1078",
            "--input", str(input_path),
            "--output", str(output_path),
        ],
    )

    assert invocation.exit_code == 1
    assert "Validation failed" in invocation.stdout
    assert not output_path.exists()


def test_report_multiple_findings_write_nothing(tmp_path: Path, monkeypatch) -> None:
    from duke.detection import detect_t1078 as real_detect

    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")
    output_path = tmp_path / "incident.md"

    def two_findings(events):
        findings = real_detect(events)
        return (findings[0], findings[0])

    monkeypatch.setattr("duke.cli.app.detect_t1078", two_findings)

    invocation = runner.invoke(
        app,
        [
            "report", "T1078",
            "--input", str(input_path),
            "--output", str(output_path),
        ],
    )

    assert invocation.exit_code == 1
    assert "Expected exactly one finding" in invocation.stdout
    assert not output_path.exists()


def test_report_runs_validation_exactly_once(tmp_path: Path, monkeypatch) -> None:
    from duke.validation import validate_t1078 as real_validate

    calls = {"count": 0}

    def counting(artefact):
        calls["count"] += 1
        return real_validate(artefact)

    monkeypatch.setattr("duke.cli.app.validate_t1078", counting)
    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")
    output_path = tmp_path / "incident.md"

    invocation = runner.invoke(
        app,
        [
            "report", "T1078",
            "--input", str(input_path),
            "--output", str(output_path),
        ],
    )

    assert invocation.exit_code == 0
    assert calls["count"] == 1


def test_report_does_not_modify_input_file(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    input_path = export_simulation(result, tmp_path / "t1078.json")
    before = input_path.read_bytes()
    output_path = tmp_path / "incident.md"

    runner.invoke(
        app,
        [
            "report", "T1078",
            "--input", str(input_path),
            "--output", str(output_path),
        ],
    )

    assert input_path.read_bytes() == before
