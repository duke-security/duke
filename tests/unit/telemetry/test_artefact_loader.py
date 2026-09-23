"""Tests for loading normalized telemetry artefacts."""

import json
from pathlib import Path

import pytest

from duke.core import SecurityEvent
from duke.simulation import (
    export_simulation,
    generate_t1078_simulation,
    simulation_payload,
)
from duke.telemetry import EventLoadError, load_events, load_telemetry_artefact


def _write(path: Path, name: str, payload: object) -> Path:
    target = path / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_load_events_reads_valid_exported_artefact(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    path = export_simulation(result, tmp_path / "t1078.json")

    events = load_events(path)

    assert len(events) == 8
    assert all(isinstance(event, SecurityEvent) for event in events)
    assert events[0].action == "authenticate"


def test_load_events_missing_path(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    with pytest.raises(EventLoadError, match="not found or not a regular file"):
        load_events(missing)


def test_load_events_directory_is_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "dir"
    directory.mkdir()

    with pytest.raises(EventLoadError, match="not a regular file"):
        load_events(directory)


def test_load_events_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{ not json", encoding="utf-8")

    with pytest.raises(EventLoadError, match="Malformed JSON"):
        load_events(path)


def test_load_events_unsupported_schema_version(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "v2.json",
        {
            "schema_version": "2.0",
            "scenario": {},
            "entities": [],
            "events": [],
        },
    )

    with pytest.raises(EventLoadError, match="Unsupported schema version"):
        load_events(path)


def test_load_events_missing_events_list(tmp_path: Path) -> None:
    path = _write(tmp_path, "no-events.json", {"schema_version": "1.0"})

    with pytest.raises(EventLoadError, match="'events' list"):
        load_events(path)


def test_load_events_invalid_event_record(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    payload = simulation_payload(result)
    payload["events"][0].pop("occurred_at")
    path = _write(tmp_path, "invalid-event.json", payload)

    with pytest.raises(EventLoadError, match="Invalid SecurityEvent at index 0"):
        load_events(path)


def test_load_telemetry_artefact_reads_entities_and_events(
    tmp_path: Path,
) -> None:
    result = generate_t1078_simulation()
    path = export_simulation(result, tmp_path / "t1078.json")

    artefact = load_telemetry_artefact(path)

    assert artefact.entities == result.entities
    assert artefact.events == result.events


def test_load_telemetry_artefact_requires_entities(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    payload = simulation_payload(result)
    payload.pop("entities")
    path = _write(tmp_path, "no-entities.json", payload)

    with pytest.raises(EventLoadError, match="'entities' list"):
        load_telemetry_artefact(path)


def test_load_telemetry_artefact_rejects_invalid_entity(
    tmp_path: Path,
) -> None:
    result = generate_t1078_simulation()
    payload = simulation_payload(result)
    payload["entities"][0].pop("identifier")
    path = _write(tmp_path, "invalid-entity.json", payload)

    with pytest.raises(EventLoadError, match="Invalid Entity at index 0"):
        load_telemetry_artefact(path)
