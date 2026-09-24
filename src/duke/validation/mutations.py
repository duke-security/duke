"""Controlled in-memory mutations for detection-rule validation.

Every mutation builds a brand-new :class:`TelemetryArtefact` from copied
or new model instances (immutable tuples and :meth:`SecurityEvent.model_copy`
``update``); the input artefact is never modified. Each event is copied
rather than reused by reference where an attribute changes, and cloned
events receive a distinct deterministic ID so no two events ever share an
identifier. This keeps validation side-effect-free and its source data
immutable.
"""

from collections.abc import Callable, Iterable
from datetime import timedelta
from uuid import UUID, uuid5

from duke.core import SecurityEvent
from duke.telemetry import TelemetryArtefact

# Deterministic namespace for cloned events so duplicate-behaviour
# validation produces repeatable, distinct event IDs.
_CLONE_NAMESPACE = UUID("1078c000-0000-4000-8000-000000000000")

_UNFAMILIAR_DEVICE_IDENTIFIER = "device-unknown-442"

Mutation = Callable[[TelemetryArtefact], TelemetryArtefact]


def _attr(event: SecurityEvent, key: str) -> str | None:
    """Return a normalized event attribute, or ``None`` if absent."""
    return event.attributes.get(key)


def _is_baseline_auth(event: SecurityEvent) -> bool:
    """Return whether an event is a successful login from known context."""
    return (
        event.action == "authenticate"
        and _attr(event, "network_context") == "known"
        and _attr(event, "device_context") == "known"
    )


def _is_new_context_login(event: SecurityEvent) -> bool:
    """Return whether an event is a successful login from new context."""
    return (
        event.action == "authenticate"
        and _attr(event, "network_context") == "new"
        and _attr(event, "device_context") == "unfamiliar"
    )


def _follow_on_key(event: SecurityEvent) -> str | None:
    """Map an event to a correlated follow-on behaviour key, or ``None``."""
    if event.action == "enumerate_repository":
        return "enumerate_repository"
    if (
        event.action == "read_file"
        and _attr(event, "data_classification") == "restricted"
    ):
        return "restricted_read"
    if event.action == "request_privileged_access":
        return "privileged_request"
    if event.action == "create_archive":
        return "archive_create"
    if event.action == "network_connect":
        return "egress"
    return None


def _with_events(
    artefact: TelemetryArtefact,
    events: Iterable[SecurityEvent],
) -> TelemetryArtefact:
    """Return a new artefact sharing entities but with the given events."""
    return TelemetryArtefact(entities=artefact.entities, events=tuple(events))


def identity(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Return the artefact unchanged (used by non-mutating cases)."""
    return artefact


def remove_known_good_baseline(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Drop the known-good baseline authentication event."""
    return _with_events(
        artefact,
        (event for event in artefact.events if not _is_baseline_auth(event)),
    )


def remove_new_context_login(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Drop the new-context authentication (anchor) event."""
    return _with_events(
        artefact,
        (event for event in artefact.events if not _is_new_context_login(event)),
    )


def reduce_below_threshold(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Remove enough high-weight follow-ons to drop confidence below 60."""
    return _with_events(
        artefact,
        (
            event
            for event in artefact.events
            if not (
                (event.action == "read_file")
                or event.action == "request_privileged_access"
                or event.action == "network_connect"
            )
        ),
    )


def expire_correlation_window(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Shift follow-on behaviours outside the 15-minute correlation window."""
    events = [
        (
            event.model_copy(
                update={"occurred_at": event.occurred_at + timedelta(minutes=30)}
            )
            if _follow_on_key(event) is not None
            else event
        )
        for event in artefact.events
    ]
    return _with_events(artefact, events)


def reassign_follow_ons_to_other_actor(
    artefact: TelemetryArtefact,
) -> TelemetryArtefact:
    """Re-attribute follow-on behaviours to an actor without a baseline."""
    device = next(
        (
            entity
            for entity in artefact.entities
            if entity.identifier == _UNFAMILIAR_DEVICE_IDENTIFIER
        ),
        None,
    )
    actor_id = device.id if device is not None else None

    def _updated(event: SecurityEvent) -> SecurityEvent:
        if _follow_on_key(event) is None:
            return event
        return event.model_copy(update={"actor_entity_id": actor_id})

    return _with_events(artefact, (_updated(event) for event in artefact.events))


def duplicate_follow_on(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Insert a cloned follow-on event with a distinct deterministic ID."""
    events = list(artefact.events)
    target = next(
        (event for event in events if event.action == "enumerate_repository"),
        None,
    )
    if target is None:
        return artefact
    clone = target.model_copy(
        update={"id": uuid5(_CLONE_NAMESPACE, f"{target.id}:clone")}
    )
    index = events.index(target)
    events.insert(index + 1, clone)
    return _with_events(artefact, events)


def remove_action(action: str) -> Mutation:
    """Build a mutation that drops every event with the given action."""

    def _mutate(artefact: TelemetryArtefact) -> TelemetryArtefact:
        return _with_events(
            artefact,
            (event for event in artefact.events if event.action != action),
        )

    return _mutate


def benign_only_routine(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Keep only the known-good baseline and routine application access."""
    return _with_events(
        artefact,
        (
            event
            for event in artefact.events
            if _follow_on_key(event) is None
            and not _is_new_context_login(event)
        ),
    )
