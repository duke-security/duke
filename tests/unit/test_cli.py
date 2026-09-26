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


def _t1078_registry_with(**capability_overrides):
    """Return a registry whose T1078 registration has capability overrides.

    Used to exercise CLI dispatch against a scenario that differs from the
    built-in T1078 registration (e.g. a replaced or missing capability).
    """
    import dataclasses

    from duke.scenarios.builtins import t1078_registration
    from duke.scenarios.registry import ScenarioRegistry

    base = t1078_registration()
    caps = dataclasses.replace(base.capabilities, **capability_overrides)
    registration = dataclasses.replace(base, capabilities=caps)
    registry = ScenarioRegistry()
    registry.register(registration)
    return registry


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


def test_simulate_t1110_writes_json_artifact(tmp_path: Path) -> None:
    output_path = tmp_path / "t1110-session-001.json"

    result = runner.invoke(
        app,
        ["simulate", "T1110", "--output", str(output_path)],
    )

    assert result.exit_code == 0
    assert "Simulation complete" in result.stdout
    assert "Events generated: 8" in result.stdout
    assert output_path.exists()

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["scenario"]["attack_technique_id"] == "T1110"
    assert len(payload["events"]) == 8


def test_simulate_t1110_resolves_all_aliases(tmp_path: Path) -> None:
    for key in ("T1110", "t1110", "t1110_brute_force", "brute-force", "T1110.003"):
        output_path = tmp_path / f"out-{key.replace('.', '-')}.json"
        result = runner.invoke(
            app,
            ["simulate", key, "--output", str(output_path)],
        )
        assert result.exit_code == 0, key
        assert output_path.exists(), key


def test_simulate_t1110_requires_force_to_overwrite(tmp_path: Path) -> None:
    output_path = tmp_path / "t1110.json"

    first = runner.invoke(
        app,
        ["simulate", "T1110", "--output", str(output_path)],
    )
    second = runner.invoke(
        app,
        ["simulate", "T1110", "--output", str(output_path)],
    )
    forced = runner.invoke(
        app,
        ["simulate", "T1110", "--output", str(output_path), "--force"],
    )

    assert first.exit_code == 0
    assert second.exit_code == 1
    assert "Output already exists" in second.stdout
    assert forced.exit_code == 0


def test_detect_t1110_reads_input_artifact(tmp_path: Path) -> None:
    """duke detect T1110 reads a simulated artefact and reports one finding."""
    input_path = tmp_path / "t1110.json"
    simulated = runner.invoke(
        app,
        ["simulate", "T1110", "--output", str(input_path)],
    )
    assert simulated.exit_code == 0

    result = runner.invoke(app, ["detect", "T1110", "--input", str(input_path)])

    assert result.exit_code == 0
    assert "Detection complete" in result.stdout
    assert "Findings: 1" in result.stdout
    assert "Confidence: 80/100" in result.stdout
    assert "compromise is not confirmed" in result.stdout.lower()


def test_detect_t1110_no_findings_on_benign_artifact(tmp_path: Path) -> None:
    """A benign artefact (no spray) yields no T1110 finding, exit 0."""
    input_path = tmp_path / "benign.json"
    benign = json.dumps(
        {
            "schema_version": "1.0",
            "scenario": {"attack_technique_id": "T1110"},
            "entities": [],
            "events": [
                {
                    "occurred_at": "2026-09-25T09:00:00+00:00",
                    "action": "authenticate",
                    "outcome": "success",
                    "source": "identity_provider",
                    "attributes": {},
                }
            ],
        }
    )
    input_path.write_text(benign, encoding="utf-8")

    result = runner.invoke(app, ["detect", "T1110", "--input", str(input_path)])

    assert result.exit_code == 0
    assert "No findings" in result.stdout


def test_investigate_t1110_reads_input_artifact(tmp_path: Path) -> None:
    """duke investigate T1110 reads a simulated artefact and reports an
    evidence-led investigation for the single finding."""
    input_path = tmp_path / "t1110.json"
    simulated = runner.invoke(
        app,
        ["simulate", "T1110", "--output", str(input_path)],
    )
    assert simulated.exit_code == 0

    result = runner.invoke(app, ["investigate", "T1110", "--input", str(input_path)])

    assert result.exit_code == 0
    assert "Investigation complete" in result.stdout
    assert "Password spray against multiple distinct accounts" in result.stdout
    assert "Evidence items:" in result.stdout
    assert "Timeline:" in result.stdout
    assert "Confirmed facts:" in result.stdout
    assert "Analyst assessments:" in result.stdout
    assert "Unresolved questions:" in result.stdout


def test_t1110_unsupported_lifecycle_capabilities_exit_2(
    tmp_path: Path,
) -> None:
    """Commands whose capabilities T1110 does not yet provide fail with exit 2
    through the missing-capability path before reading any input file."""
    input_path = tmp_path / "t1110.json"
    simulated = runner.invoke(
        app,
        ["simulate", "T1110", "--output", str(input_path)],
    )
    assert simulated.exit_code == 0
    before = input_path.read_bytes()

    for command, expected_capability in (
        # respond resolves detection + investigation (both present) then
        # response (missing).
        ("respond", "response"),
        # report resolves detection (present) then validation (missing).
        ("report", "validation"),
        ("validate", "validation"),
    ):
        result = runner.invoke(app, [command, "T1110", "--input", str(input_path)])
        assert result.exit_code == 2, command
        assert "does not provide capability" in result.stdout, command
        assert expected_capability in result.stdout, command
        # The input artefact was never read, modified, or replaced.
        assert input_path.read_bytes() == before, command

    # learn takes no --input path; confirm it fails on its own via the same
    # missing-capability path.
    result = runner.invoke(app, ["learn", "T1110"])
    assert result.exit_code == 2
    assert "does not provide capability" in result.stdout
    assert "learning" in result.stdout


def test_scenarios_lists_t1110_with_simulation_detection_investigation() -> None:
    result = runner.invoke(app, ["scenarios"])

    assert result.exit_code == 0
    assert "T1110" in result.stdout
    assert "Brute Force: Password Spraying" in result.stdout
    assert "t1110_brute_force" in result.stdout
    assert "brute-force" in result.stdout
    assert "T1110.003" in result.stdout
    # T1110 advertises simulation, detection, and investigation (other
    # capabilities are intentionally not yet provided).
    assert "simulation" in result.stdout
    assert "detection" in result.stdout
    assert "investigation" in result.stdout
    assert "T1078" in result.stdout


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

    monkeypatch.setattr(
        "duke.cli.app.REGISTRY",
        _t1078_registry_with(validation=failing),
    )
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

    monkeypatch.setattr(
        "duke.cli.app.REGISTRY",
        _t1078_registry_with(detection=two_findings),
    )

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

    monkeypatch.setattr(
        "duke.cli.app.REGISTRY",
        _t1078_registry_with(validation=counting),
    )
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


def test_learn_lists_all_steps_in_overview() -> None:
    result = runner.invoke(app, ["learn", "T1078"])

    assert result.exit_code == 0
    assert "T1078" in result.stdout
    assert "Steps" in result.stdout
    for step_id in (
        "orientation",
        "collections",
        "typed-models",
        "datetime",
        "functions-modules",
        "detection",
        "investigation",
        "response",
        "validation",
        "reporting",
        "final-challenge",
    ):
        assert step_id in result.stdout


def test_learn_render_step_detection() -> None:
    result = runner.invoke(app, ["learn", "T1078", "--step", "detection"])

    assert result.exit_code == 0
    assert "Step 6: Detection reasoning" in result.stdout
    assert "Objective:" in result.stdout
    assert "Python concepts:" in result.stdout
    assert "Command examples:" in result.stdout
    assert "Exercise:" in result.stdout
    assert "Knowledge check:" in result.stdout
    assert "Reference answer (self-check)" in result.stdout
    assert "Safety note:" in result.stdout


def test_learn_render_step_investigation() -> None:
    result = runner.invoke(app, ["learn", "T1078", "--step", "investigation"])

    assert result.exit_code == 0
    assert "Step 7: Evidence-led investigation" in result.stdout
    assert "duke investigate T1078" in result.stdout


def test_learn_render_step_final_challenge() -> None:
    result = runner.invoke(app, ["learn", "T1078", "--step", "final-challenge"])

    assert result.exit_code == 0
    assert "Step 11: Final challenge: the full learning loop" in result.stdout
    assert "duke simulate T1078" in result.stdout
    assert "duke report T1078" in result.stdout


def test_learn_unknown_step_exits_2() -> None:
    result = runner.invoke(app, ["learn", "T1078", "--step", "does-not-exist"])

    assert result.exit_code == 2
    assert "Unknown step" in result.stdout


def test_learn_unsupported_technique_exits_2() -> None:
    result = runner.invoke(app, ["learn", "T9999"])

    assert result.exit_code == 2
    assert "Unsupported technique" in result.stdout


def test_learn_does_not_write_any_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    before = {p for p in tmp_path.rglob("*")}

    result = runner.invoke(app, ["learn", "T1078"])
    assert result.exit_code == 0

    result_detection = runner.invoke(app, ["learn", "T1078", "--step", "detection"])
    assert result_detection.exit_code == 0

    after = {p for p in tmp_path.rglob("*")}
    assert before == after


def test_learn_output_is_literal_and_rich_safe() -> None:
    """Lesson text with brackets/dicts/annotations must not be swallowed."""
    result = runner.invoke(app, ["learn", "T1078", "--step", "collections"])

    assert result.exit_code == 0
    assert "dict[str, int]" in result.stdout
    assert "counts.get(action, 0)" in result.stdout


def test_scenarios_lists_registered_scenario() -> None:
    result = runner.invoke(app, ["scenarios"])

    assert result.exit_code == 0
    assert "T1078" in result.stdout
    assert "Valid Accounts: Compromised Identity" in result.stdout
    assert "t1078_valid_accounts" in result.stdout
    assert "valid-accounts" in result.stdout
    for capability in (
        "simulation",
        "detection",
        "investigation",
        "response",
        "validation",
        "reporting",
        "learning",
    ):
        assert capability in result.stdout


def test_scenarios_shows_capabilities_in_lifecycle_order() -> None:
    result = runner.invoke(app, ["scenarios"])
    order = (
        "simulation",
        "detection",
        "investigation",
        "response",
        "validation",
        "reporting",
        "learning",
    )
    positions = [result.stdout.index(cap) for cap in order]
    assert positions == sorted(positions)


def test_learn_resolves_case_insensitive_slug_and_alias() -> None:
    for key in ("T1078", "t1078", "t1078_valid_accounts", "valid-accounts"):
        result = runner.invoke(app, ["learn", key])
        assert result.exit_code == 0
        assert "T1078 Guided Learning Path" in result.stdout


def test_detect_resolves_via_lowercase_and_slug(tmp_path: Path) -> None:
    input_path = tmp_path / "events.json"
    simulated = runner.invoke(
        app, ["simulate", "T1078", "--output", str(input_path)]
    )
    assert simulated.exit_code == 0

    for key in ("t1078", "t1078_valid_accounts", "valid-accounts"):
        result = runner.invoke(app, ["detect", key, "--input", str(input_path)])
        assert result.exit_code == 0
        assert "Findings" in result.stdout


def test_detect_missing_capability_exits_2_without_execution(
    tmp_path: Path, monkeypatch
) -> None:
    """A registered scenario lacking a capability fails clearly (revision 7)."""
    registry = _t1078_registry_with(detection=None)
    monkeypatch.setattr("duke.cli.app.REGISTRY", registry)

    input_path = tmp_path / "no-events.json"
    result = runner.invoke(
        app, ["detect", "T1078", "--input", str(input_path)]
    )

    assert result.exit_code == 2
    assert "does not provide capability" in result.stdout
    # No capability ran and no artefact was read or produced.
    assert not input_path.exists()


def test_cli_has_no_hardcoded_t1078_dispatch() -> None:
    """Dispatch must go through the registry, not a hardcoded technique check.

    This is a narrow, structural check: the CLI must not import any
    T1078-specific capability function and must not contain the old
    ``technique.upper() != "T1078"`` style guard. It does not forbid the
    literal text "T1078" (help examples and default filenames keep it).
    """
    import ast

    source_path = Path(__file__).resolve().parents[2] / "src/duke/cli/app.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported.add(alias.asname or alias.name)

    t1078_capabilities = {
        "generate_t1078_simulation",
        "detect_t1078",
        "investigate_t1078",
        "plan_t1078_response",
        "validate_t1078",
        "report_t1078",
        "t1078_learning_path",
    }
    assert not (imported & t1078_capabilities)

    # Dispatch is registry-driven: it must import the registry root and the
    # capability-selection helper, and must not compare the technique string.
    assert "builtin_registry" in imported
    assert "required_capability" in imported
    assert "technique.upper()" not in source
    assert '== "T1078"' not in source
    assert '!= "T1078"' not in source
