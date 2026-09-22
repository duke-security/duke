"""Tests for loading normalized events from exported artefacts."""

import json
from pathlib import Path

import pytest

from duke.core import SecurityEvent
from duke.detection.events import EventLoadError, load_events
from duke.simulation import (
    export_simulation,
    generate_t1078_simulation,
    simulation_payload,
)


def _write(tmp_path: Path, name: str, payload: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_load_events_reads_valid_exported_artefact(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    path = export_simulation(result, tmp_path / "t1078.json")

    events = load_events(path)

    assert len(events) == 8
    assert all(isinstance(e, SecurityEvent) for e in events)
    assert events[0].action == "authenticate"


def test_load_events_missing_path(tmp_path: Path) -> None:
    path = tmp_path / "missing.json"

    with pytest.raises(EventLoadError, match="not a regular file"):
        load_events(path)


def test_load_events_directory_is_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "a-directory"
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
        {"schema_version": "2.0", "scenario": {}, "entities": [], "events": []},
    )

    with pytest.raises(EventLoadError, match="Unsupported schema version"):
        load_events(path)


def test_load_events_missing_events_list(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "noevents.json",
        {"schema_version": "1.0", "scenario": {}, "entities": []},
    )

    with pytest.raises(EventLoadError, match="'events' list"):
        load_events(path)


def test_load_events_invalid_event_record(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    payload = simulation_payload(result)
    payload["events"][0].pop("occurred_at")
    path = _write(tmp_path, "badevent.json", payload)

    with pytest.raises(EventLoadError, match="Invalid SecurityEvent at index 0"):
        load_events(path)
