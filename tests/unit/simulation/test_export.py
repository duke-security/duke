"""Tests for simulation artefact export."""

import json
from pathlib import Path

import pytest

from duke.simulation import (
    export_simulation,
    generate_t1078_simulation,
    generate_t1110_simulation,
    simulation_payload,
)
from duke.telemetry import load_telemetry_artefact


def test_payload_contains_scenario_entities_and_events() -> None:
    result = generate_t1078_simulation()

    payload = simulation_payload(result)

    assert payload["schema_version"] == "1.0"
    assert payload["scenario"]["attack_technique_id"] == "T1078"
    assert len(payload["entities"]) == 8
    assert len(payload["events"]) == 8


def test_export_writes_valid_json(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    output_path = tmp_path / "events" / "t1078-session-001.json"

    saved_path = export_simulation(result, output_path)
    payload = json.loads(saved_path.read_text(encoding="utf-8"))

    assert saved_path == output_path
    assert payload["scenario"]["name"] == "Valid Accounts: Compromised Identity"
    assert payload["events"][0]["action"] == "authenticate"


def test_export_does_not_overwrite_by_default(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    output_path = tmp_path / "t1078-session-001.json"
    output_path.write_text("existing evidence", encoding="utf-8")

    with pytest.raises(FileExistsError, match="Output already exists"):
        export_simulation(result, output_path)

    assert output_path.read_text(encoding="utf-8") == "existing evidence"


def test_export_can_overwrite_when_explicitly_requested(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    output_path = tmp_path / "t1078-session-001.json"
    output_path.write_text("old data", encoding="utf-8")

    export_simulation(result, output_path, overwrite=True)
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "1.0"


def test_t1110_export_round_trips_through_telemetry_loader(tmp_path: Path) -> None:
    """A T1110 artefact exports deterministically and loads back through the
    existing telemetry loader with identical entities and events (no schema
    change needed)."""
    result = generate_t1110_simulation()
    output_path = tmp_path / "t1110-session-001.json"

    saved = export_simulation(result, output_path)
    artefact = load_telemetry_artefact(saved)

    assert artefact.entities == result.entities
    assert artefact.events == result.events
    assert len(artefact.events) == 8


def test_t1110_payload_contains_scenario_entities_and_events() -> None:
    result = generate_t1110_simulation()

    payload = simulation_payload(result)

    assert payload["schema_version"] == "1.0"
    assert payload["scenario"]["attack_technique_id"] == "T1110"
    assert payload["scenario"]["attack_tactics"] == ["Credential Access"]
    assert len(payload["entities"]) == 10
    assert len(payload["events"]) == 8


def test_t1110_export_is_deterministic(tmp_path: Path) -> None:
    """Re-exporting the same simulation twice yields byte-identical files."""
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"

    export_simulation(generate_t1110_simulation(), first_path)
    export_simulation(generate_t1110_simulation(), second_path)

    assert first_path.read_bytes() == second_path.read_bytes()
