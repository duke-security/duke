"""Compatibility tests for detection's re-export of the telemetry loader.

Artefact loading lives in ``duke.telemetry`` and is tested there. These
tests only assert that ``duke.detection`` continues to re-export the
``load_events`` entry point for the ``duke detect`` command.
"""

from pathlib import Path

from duke.core import SecurityEvent
from duke.detection import EventLoadError, load_events
from duke.simulation import export_simulation, generate_t1078_simulation


def test_detection_reexports_events_loader(tmp_path: Path) -> None:
    result = generate_t1078_simulation()
    path = export_simulation(result, tmp_path / "t1078.json")

    events = load_events(path)

    assert len(events) == 8
    assert all(isinstance(event, SecurityEvent) for event in events)


def test_detection_reexports_event_load_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    try:
        load_events(missing)
    except EventLoadError:
        pass
    else:  # pragma: no cover - the re-export is what we are asserting.
        raise AssertionError("load_events should have raised EventLoadError")
