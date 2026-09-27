"""Controlled in-memory mutations for T1110 validation.

Every mutation builds a brand-new :class:`TelemetryArtefact` from copied or
new model instances; the input artefact is never modified. Newly created
events and entities receive distinct deterministic UUIDs (via ``uuid5``,
with events and entities in separate namespaces) so no two objects share an
identifier and every new actor, account, service, or target is backed by a
real, resolvable entity. Mutations are expressed through observable event
properties (outcome, actor, targets, timestamps), never through private
implementation details. No wall-clock, randomness, or mutable shared state is
used.
"""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5

from duke.core import Entity, EntityType, EventOutcome, SecurityEvent
from duke.telemetry import TelemetryArtefact

# Deterministic namespaces: events and entities are deliberately kept in
# separate namespaces so a cloned-event ID and a created-entity ID can never
# collide.
_EVENT_NAMESPACE = UUID("1110d000-0000-4000-8000-000000000000")
_ENTITY_NAMESPACE = UUID("1110d001-0000-4000-8000-000000000000")

# Canonical corpus identifiers used to express observable mutations.
_SOURCE_IDENTIFIER = "host-198.51.100.77"
_PORTAL_IDENTIFIER = "web-portal"
_FIRST_ACCOUNT_IDENTIFIER = "svc.integration"

_BASE_TIME = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


def _with(
    artefact: TelemetryArtefact,
    events: tuple[SecurityEvent, ...],
    entities: tuple[Entity, ...],
) -> TelemetryArtefact:
    """Return a new artefact with the given entities and events."""
    return TelemetryArtefact(entities=entities, events=events)


def _new_entity(
    identifier: str,
    entity_type: EntityType,
    display_name: str,
    **attributes: str,
) -> Entity:
    return Entity(
        id=uuid5(_ENTITY_NAMESPACE, f"entity:{identifier}"),
        entity_type=entity_type,
        identifier=identifier,
        display_name=display_name,
        attributes=attributes,
    )


def _clone_id(event: SecurityEvent, key: str) -> UUID:
    return uuid5(_EVENT_NAMESPACE, f"{event.id}:{key}")


def _spray_failure(event: SecurityEvent) -> bool:
    return event.action == "authenticate" and event.outcome is EventOutcome.FAILURE


def _success(event: SecurityEvent) -> bool:
    return event.action == "authenticate" and event.outcome is EventOutcome.SUCCESS


def _entity_by_identifier(
    artefact: TelemetryArtefact, identifier: str
) -> Entity | None:
    for entity in artefact.entities:
        if entity.identifier == identifier:
            return entity
    return None


def _ordered_failures(artefact: TelemetryArtefact) -> list[SecurityEvent]:
    return sorted(
        (e for e in artefact.events if _spray_failure(e)),
        key=lambda e: (e.occurred_at, e.id),
    )


def _spray_success(artefact: TelemetryArtefact) -> SecurityEvent | None:
    """Return the later spray success (same actor as the failures), or None.

    The canonical corpus also contains a benign baseline success from a
    different actor; it is deliberately never selected.
    """
    failures = [e for e in artefact.events if _spray_failure(e)]
    if not failures:
        return None
    source_id = failures[0].actor_entity_id
    for event in artefact.events:
        if (
            _success(event)
            and event.actor_entity_id == source_id
            and event.actor_entity_id is not None
        ):
            return event
    return None


# ---- mutations --------------------------------------------------------------\


def identity(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Return the artefact unchanged (used by non-mutating cases)."""
    return artefact


def remove_later_success(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Drop the later successful authentication."""
    events = tuple(event for event in artefact.events if not _success(event))
    return _with(artefact, events, artefact.entities)


def retarget_success_to_unrelated_account(
    artefact: TelemetryArtefact,
) -> TelemetryArtefact:
    """Point the later (spray) success at a brand-new never-failed account."""
    success = _spray_success(artefact)
    portal = _entity_by_identifier(artefact, _PORTAL_IDENTIFIER)
    if success is None:
        return artefact
    new_account = _new_entity(
        "g.hanks", EntityType.ACCOUNT, "G. Hanks", account_type="human"
    )
    targets = (
        [portal.id, new_account.id] if portal is not None else [new_account.id]
    )
    updated = success.model_copy(
        update={
            "id": _clone_id(success, "retarget"),
            "target_entity_ids": targets,
        }
    )
    events = tuple(
        updated if event is success else event for event in artefact.events
    )
    return _with(artefact, events, (*artefact.entities, new_account))


def move_success_outside_window(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Shift the later (spray) success beyond the 30-minute detection window."""
    failures = _ordered_failures(artefact)
    success = _spray_success(artefact)
    if not failures or success is None:
        return artefact
    window_end = failures[0].occurred_at + timedelta(minutes=31)
    updated = success.model_copy(
        update={
            "id": _clone_id(success, "outside"),
            "occurred_at": window_end,
        }
    )
    events = tuple(
        updated if event is success else event for event in artefact.events
    )
    return _with(artefact, events, artefact.entities)


def move_success_before_failure(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Move the later (spray) success strictly before its account's failure."""
    success = _spray_success(artefact)
    failures = _ordered_failures(artefact)
    if success is None or not failures:
        return artefact
    updated = success.model_copy(
        update={
            "id": _clone_id(success, "before"),
            "occurred_at": failures[0].occurred_at - timedelta(minutes=1),
        }
    )
    events = tuple(
        updated if event is success else event for event in artefact.events
    )
    return _with(artefact, events, artefact.entities)


def reduce_distinct_accounts(
    keep: int, drop_success: bool
) -> Callable[[TelemetryArtefact], TelemetryArtefact]:
    """Return a mutation keeping only ``keep`` distinct failed accounts.

    The latest failure events (by time, then ID) are dropped so only ``keep``
    distinct sprayed accounts remain. ``drop_success`` also removes the later
    success so the case isolates the account-count boundary.
    """

    def _mutate(artefact: TelemetryArtefact) -> TelemetryArtefact:
        failures = _ordered_failures(artefact)
        kept = tuple(failures[:keep])
        events = [
            event
            for event in artefact.events
            if not _spray_failure(event)
        ]
        if drop_success:
            events = [event for event in events if not _success(event)]
        events.extend(kept)
        return _with(artefact, tuple(events), artefact.entities)

    return _mutate


def clone_failure_same_account(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Clone one failure against an already-counted account and drop success."""
    failures = [e for e in artefact.events if _spray_failure(e)]
    events = [e for e in artefact.events if not _success(e)]
    if failures:
        original = failures[0]
        events.append(
            original.model_copy(update={"id": _clone_id(original, "repeat")})
        )
    return _with(artefact, tuple(events), artefact.entities)


def add_shared_service(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Add a real, resolvable shared-service Entity targeted by every failure.

    The canonical credited success behaviour is left unchanged.
    """
    service = _new_entity(
        "auth-gateway",
        EntityType.APPLICATION,
        "Auth Gateway",
        resource_type="identity_service",
    )
    events = []
    for event in artefact.events:
        if _spray_failure(event):
            events.append(
                event.model_copy(
                    update={
                        "id": _clone_id(event, "service"),
                        "target_entity_ids": [*event.target_entity_ids, service.id],
                    }
                )
            )
        else:
            events.append(event)
    return _with(artefact, tuple(events), (*artefact.entities, service))


def split_failures_across_sources(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Distribute failures across two source actors so neither qualifies."""
    source_b = _new_entity(
        "host-203-0-113-9",
        EntityType.HOST,
        "Secondary Source Host",
        managed="false",
        zone="internet",
    )
    other = [e for e in artefact.events if not _spray_failure(e)]
    events = list(other)
    for index, event in enumerate(
        e for e in artefact.events if _spray_failure(e)
    ):
        actor = source_b.id if index % 2 == 0 else event.actor_entity_id
        events.append(
            event.model_copy(
                update={
                    "id": _clone_id(event, f"split-{index}"),
                    "actor_entity_id": actor,
                }
            )
        )
    return _with(artefact, tuple(events), (*artefact.entities, source_b))


def single_account_guessing(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Retarget every failure to the same account."""
    first = _entity_by_identifier(artefact, _FIRST_ACCOUNT_IDENTIFIER)
    portal = _entity_by_identifier(artefact, _PORTAL_IDENTIFIER)
    if first is None:
        return artefact
    events = []
    for index, event in enumerate(artefact.events):
        if _spray_failure(event):
            targets = [portal.id, first.id] if portal is not None else [first.id]
            events.append(
                event.model_copy(
                    update={
                        "id": _clone_id(event, f"single-{index}"),
                        "target_entity_ids": targets,
                    }
                )
            )
        else:
            events.append(event)
    return _with(artefact, tuple(events), artefact.entities)


def add_unrelated_early_failure(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Insert an unrelated early failure (a 7th distinct account) far before the
    spray, from the same source, so the sliding window ignores it."""
    early_account = _new_entity(
        "early.user", EntityType.ACCOUNT, "Early User", account_type="human"
    )
    portal = _entity_by_identifier(artefact, _PORTAL_IDENTIFIER)
    failures = [e for e in artefact.events if _spray_failure(e)]
    if not failures or portal is None:
        return artefact
    earliest = min(e.occurred_at for e in failures)
    early = SecurityEvent(
        id=uuid5(_EVENT_NAMESPACE, "early-failure"),
        occurred_at=earliest - timedelta(minutes=60),
        action="authenticate",
        outcome=EventOutcome.FAILURE,
        source="identity_provider",
        actor_entity_id=failures[0].actor_entity_id,
        target_entity_ids=[portal.id, early_account.id],
        attributes={},
    )
    events = (*artefact.events, early)
    return _with(artefact, events, (*artefact.entities, early_account))


def spread_failures_beyond_window(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Space failures more than 30 minutes apart so no window qualifies."""
    failures = _ordered_failures(artefact)
    other = [e for e in artefact.events if not _spray_failure(e)]
    if not failures:
        return artefact
    base = failures[0].occurred_at
    events = list(other)
    for index, event in enumerate(failures):
        events.append(
            event.model_copy(
                update={
                    "id": _clone_id(event, f"spread-{index}"),
                    "occurred_at": base + index * timedelta(minutes=10),
                }
            )
        )
    return _with(artefact, tuple(events), artefact.entities)


def deterministic_two_windows(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Build two equal five-account bursts so the earliest-window tie-break wins.

    Both bursts qualify independently with equal distinct-account count (5) and
    equal failure count (5), are separated by 60 minutes so they never merge,
    and carry no success. The earlier burst must be selected deterministically.
    """
    source = _new_entity(
        _SOURCE_IDENTIFIER, EntityType.HOST, "External Source Host",
        managed="false", zone="internet",
    )
    portal = _new_entity(
        _PORTAL_IDENTIFIER, EntityType.APPLICATION, "Web Portal",
        resource_type="identity_service",
    )
    assets = [
        _new_entity(f"acct-{i}", EntityType.ACCOUNT, f"Account {i}")
        for i in range(10)
    ]
    events: list[SecurityEvent] = []
    for i in range(5):
        events.append(
            SecurityEvent(
                id=uuid5(_EVENT_NAMESPACE, f"b1-f-{i}"),
                occurred_at=_BASE_TIME + i * timedelta(minutes=2),
                action="authenticate",
                outcome=EventOutcome.FAILURE,
                source="identity_provider",
                actor_entity_id=source.id,
                target_entity_ids=[portal.id, assets[i].id],
                attributes={},
            )
        )
    for i in range(5):
        events.append(
            SecurityEvent(
                id=uuid5(_EVENT_NAMESPACE, f"b2-f-{i}"),
                occurred_at=(
                    _BASE_TIME + timedelta(minutes=60) + i * timedelta(minutes=2)
                ),
                action="authenticate",
                outcome=EventOutcome.FAILURE,
                source="identity_provider",
                actor_entity_id=source.id,
                target_entity_ids=[portal.id, assets[5 + i].id],
                attributes={},
            )
        )
    entities = (source, portal, *assets)
    return _with(artefact, tuple(events), entities)


def strip_actors(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Remove ``actor_entity_id`` from every event."""
    events = tuple(
        event.model_copy(update={"actor_entity_id": None})
        for event in artefact.events
    )
    return _with(artefact, events, artefact.entities)


def benign_only(artefact: TelemetryArtefact) -> TelemetryArtefact:
    """Keep only activity not performed by the spray source (a benign control)."""
    source = _entity_by_identifier(artefact, _SOURCE_IDENTIFIER)
    source_id = source.id if source is not None else None
    events = tuple(
        event
        for event in artefact.events
        if source_id is None or event.actor_entity_id != source_id
    )
    return _with(artefact, events, artefact.entities)
