"""Load normalized telemetry from Duke's exported JSON artefacts."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from duke.core import Entity, SecurityEvent

SUPPORTED_SCHEMA_VERSION = "1.0"


class EventLoadError(Exception):
    """Raised when a normalized telemetry artefact cannot be loaded."""


@dataclass(frozen=True, slots=True)
class TelemetryArtefact:
    """Validated entities and events loaded from an exported artefact."""

    entities: tuple[Entity, ...]
    events: tuple[SecurityEvent, ...]


def _load_payload(path: Path) -> dict[str, Any]:
    """Read and validate the outer JSON document."""

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
        raise EventLoadError(f"Malformed JSON in {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise EventLoadError(
            f"Expected a JSON object in {path}, got "
            f"{type(payload).__name__}"
        )

    schema_version = payload.get("schema_version")
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise EventLoadError(
            f"Unsupported schema version {schema_version!r} "
            f"(expected {SUPPORTED_SCHEMA_VERSION!r})"
        )

    return payload


def _load_entities(payload: dict[str, Any]) -> tuple[Entity, ...]:
    """Validate normalized entities from an artefact payload."""

    raw_entities = payload.get("entities")
    if not isinstance(raw_entities, list):
        raise EventLoadError("Artefact is missing an 'entities' list")

    entities: list[Entity] = []
    for index, record in enumerate(raw_entities):
        try:
            entities.append(Entity.model_validate(record))
        except ValidationError as exc:
            raise EventLoadError(
                f"Invalid Entity at index {index}: {exc}"
            ) from exc

    return tuple(entities)


def _load_events(payload: dict[str, Any]) -> tuple[SecurityEvent, ...]:
    """Validate normalized events from an artefact payload."""

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


def load_telemetry_artefact(path: Path) -> TelemetryArtefact:
    """Load and validate entities and events from an exported artefact."""

    payload = _load_payload(path)
    return TelemetryArtefact(
        entities=_load_entities(payload),
        events=_load_events(payload),
    )


def load_events(path: Path) -> tuple[SecurityEvent, ...]:
    """Load and validate only normalized events from an exported artefact."""

    return _load_events(_load_payload(path))
