"""Tests for simulation artefact export."""

import json
from pathlib import Path

import pytest

from duke.simulation import (
    export_simulation,
    generate_t1078_simulation,
    simulation_payload,
)


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
