"""Load normalized security events from Duke's exported JSON artefacts."""

import json
from pathlib import Path

from pydantic import ValidationError

from duke.core import SecurityEvent

SUPPORTED_SCHEMA_VERSION = "1.0"


class EventLoadError(Exception):
    """Raised when a normalized-events artefact cannot be loaded."""


def load_events(path: Path) -> tuple[SecurityEvent, ...]:
    """Load and validate the normalized events from a JSON artefact.

    The artefact is the ``schema_version`` / ``events`` document written
    by ``duke simulate``. Only the ``events`` collection is consumed for
    detection; ``scenario`` and ``entities`` are not validated here.
    """
    if not path.is_file():
        raise EventLoadError(
            f"Input file not found or not a regular file: {path}"
        )

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EventLoadError(
            f"Cannot read input file {path}: {exc}"
        ) from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        # Distinct from file-access errors: the file read successfully
        # but was not well-formed JSON.
        raise EventLoadError(f"Malformed JSON in {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise EventLoadError(
            f"Expected a JSON object in {path}, got {type(payload).__name__}"
        )

    schema_version = payload.get("schema_version")
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise EventLoadError(
            f"Unsupported schema version {schema_version!r} "
            f"(expected {SUPPORTED_SCHEMA_VERSION!r})"
        )

    raw_events = payload.get("events")
    if not isinstance(raw_events, list):
        raise EventLoadError("Artefact is missing an 'events' list")

    events: list[SecurityEvent] = []
    for index, record in enumerate(raw_events):
        try:
            events.append(SecurityEvent.model_validate(record))
        except ValidationError as exc:
            raise EventLoadError(
                f"Invalid SecurityEvent at index {index}: {exc}"
            ) from exc

    return tuple(events)
