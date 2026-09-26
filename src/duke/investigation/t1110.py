"""Evidence-led investigation for the T1110.003 Password Spraying scenario.

Investigation does not run detection itself. ``investigate_t1110`` consumes an
existing ``Finding`` produced by ``detect_t1110`` and turns it, plus the
telemetry it references, into an evidence-led ``InvestigationResult``: a
chronological timeline, one ``Evidence`` per referenced event, the involved
entities, and distinct confirmed facts, analyst assessments, and unresolved
questions.

Boundaries:

- Only the events referenced by ``finding.event_ids`` are ever considered.
  Events or entities referenced by the finding that cannot be resolved from
  the supplied artefact are skipped (never substituted with unrelated data),
  and an explicit incompleteness question/assessment is added when any are
  missing.
- ``involved_entities`` come from ``finding.entity_ids`` only, so a shared
  authentication service (which detection excludes from the finding) is never
  implicated. Timeline entries preserve the original target IDs of each source
  event, including any shared-service target, because a timeline represents
  the source event faithfully.
- The result is fully deterministic: event/entity resolution and ordering use
  ``(occurred_at, str(event.id))`` and fixed ``uuid5`` evidence IDs; no wall
  clock or random identifiers are used.
- A referenced successful authentication is described only as credited /
  supporting behaviour (the detector placed it in the finding); the artefact
  is never rescanned to validate or extend that conclusion.
"""

from uuid import UUID, uuid5

from duke.core import (
    Entity,
    EntityType,
    EventOutcome,
    Evidence,
    EvidenceRelationship,
    Finding,
    SecurityEvent,
)
from duke.investigation.result import InvestigationResult, TimelineEntry
from duke.telemetry import TelemetryArtefact

# Deterministic namespace so evidence identifiers are repeatable for the same
# referenced event, mirroring the stable IDs used by simulation and detection.
_EVIDENCE_NAMESPACE = UUID("11106000-0000-4000-8000-000000000000")

_ANALYST_ASSESSMENTS = (
    "The pattern of many failed authentications against distinct accounts from "
    "a single source within a short window is consistent with password "
    "spraying (MITRE ATT&CK T1110.003).",
    "Failures may reflect hostile activity, but could also be consistent with "
    "user error, automation, or an authorized but misconfigured service; "
    "intent is not established by investigation alone.",
)

_BASE_UNRESOLVED_QUESTIONS = (
    "Was the source authorized infrastructure?",
    "Did the failures result from user error, automation, or hostile activity?",
    "Did any affected account show subsequent suspicious activity after the "
    "failures?",
    "Did the source appear elsewhere or continue activity outside the "
    "30-minute detection window?",
)

# Phrases stated conditionally on whether a referenced later success exists.
_SUCCESS_QUESTION_PRESENT = (
    "Was the successful authentication against the previously-failed account "
    "legitimate?"
)
_SUCCESS_QUESTION_ABSENT = (
    "Was any successful authentication observed after the failures?"
)

_INCOMPLETENESS_ASSESSMENT = (
    "The investigation is incomplete: one or more events or entities "
    "referenced by the finding could not be resolved from the supplied "
    "artefact."
)
_INCOMPLETENESS_QUESTION = (
    "Could any unresolved referenced events or entities be observed through "
    "another telemetry source?"
)


def _sort_key(event: SecurityEvent) -> tuple[object, str]:
    """Deterministic ordering for time-then-ID; timestamps are compared as
    ``occurred_at`` and the event ID is compared as its string form."""
    return (event.occurred_at, str(event.id))


def _is_failure(event: SecurityEvent) -> bool:
    return event.outcome is EventOutcome.FAILURE


def _is_success(event: SecurityEvent) -> bool:
    return event.outcome is EventOutcome.SUCCESS


def _account_label(
    event: SecurityEvent,
    entities_by_id: dict[UUID, Entity],
    finding_scoped_ids: set[UUID],
) -> str | None:
    """Return the identifier of the finding-scoped account this event targeted.

    Only target entities that are (a) referenced by the finding and (b)
    classified as accounts by their entity type are treated as sprayed /
    implicated accounts. Other event targets (such as a shared authentication
    service) are treated as context and never returned here.
    """
    for target_id in event.target_entity_ids:
        if target_id not in finding_scoped_ids:
            continue
        entity = entities_by_id.get(target_id)
        if entity is not None and entity.entity_type is EntityType.ACCOUNT:
            return entity.identifier
    return None


def _event_summary(
    event: SecurityEvent,
    entities_by_id: dict[UUID, Entity],
    finding_scoped_ids: set[UUID],
) -> str:
    """A short, cautious summary for one referenced event."""
    account = _account_label(event, entities_by_id, finding_scoped_ids)
    account_phrase = f" account {account!r}" if account else " a finding-scoped account"
    if _is_failure(event):
        return f"Failed authentication against{account_phrase}"
    return f"Successful authentication to{account_phrase}"


def _evidence_description(
    event: SecurityEvent,
    entities_by_id: dict[UUID, Entity],
    finding_scoped_ids: set[UUID],
) -> str:
    """What a piece of evidence shows, naming only finding-scoped accounts.

    A shared-service target (present in the event but not in the finding) is
    described only as the authentication service context, never as an
    implicated account.
    """
    account = _account_label(event, entities_by_id, finding_scoped_ids)
    if _is_success(event):
        account_phrase = (
            f" against account {account!r}" if account else ""
        )
        return (
            "A later successful authentication from the same source"
            f"{account_phrase} supports the finding that a credential may "
            "have validated. This is supporting evidence only; it does not "
            "confirm compromise."
        )
    # A failed authentication contributing to the spray window.
    if account:
        return (
            f"A failed authentication against account {account!r} supports the "
            "password-spraying pattern."
        )
    return (
        "A failed authentication was observed. No finding-scoped account "
        "target was identified in this event."
    )


def _confirmed_facts(
    resolved_events: list[SecurityEvent],
    involved: list[Entity],
    *,
    unresolved_event_count: int,
    unresolved_entity_count: int,
    finding_entity_ids: list[UUID],
) -> tuple[str, ...]:
    """Telemetry-derived facts, distinguishing referenced failures, resolved
    implicated targets, and unresolved references."""
    facts: list[str] = []

    total_failures = sum(1 for event in resolved_events if _is_failure(event))
    facts.append(
        f"The finding references {total_failures} failed authentications."
    )

    account_count = sum(
        1 for entity in involved if entity.entity_type is EntityType.ACCOUNT
    )
    facts.append(
        f"{len(involved)} of the {len(finding_entity_ids)} implicated target "
        "entities were resolved."
    )
    facts.append(
        f"{account_count} of the resolved implicated target entities are "
        "accounts."
    )

    if any(_is_success(event) for event in resolved_events):
        facts.append(
            "A later successful authentication to one previously-failed "
            "account is referenced by the finding."
        )

    # Source telemetry attributes, when the source entity is resolvable.
    source = next(
        (entity for entity in involved if entity.entity_type is EntityType.HOST),
        None,
    )
    if source is not None:
        zone = source.attributes.get("zone")
        managed = source.attributes.get("managed")
        if zone or managed:
            bits = [f"zone={zone}"] if zone else []
            if managed:
                bits.append(f"managed={managed}")
            facts.append(
                f"The source host has telemetry attributes indicating "
                f"{', '.join(bits)}."
            )

    if unresolved_event_count or unresolved_entity_count:
        facts.append(
            f"{unresolved_event_count} referenced events and "
            f"{unresolved_entity_count} implicated entities could not be "
            "resolved from the supplied artefact."
        )

    return tuple(facts)


def investigate_t1110(
    artefact: TelemetryArtefact,
    finding: Finding,
) -> InvestigationResult:
    """Build an evidence-led ``InvestigationResult`` from an existing finding.

    Only the events referenced by ``finding.event_ids`` are considered. Events
    and entities that cannot be resolved are skipped without substitution, and
    an explicit incompleteness question/assessment is added when any are
    missing. An empty or fully unresolved ``event_ids`` set yields a
    deterministic empty evidence/timeline with an incompleteness question.
    """
    events_by_id = {event.id: event for event in artefact.events}
    entities_by_id = {entity.id: entity for entity in artefact.entities}

    finding_scoped_ids = set(finding.entity_ids)

    resolved_events = [
        events_by_id[event_id]
        for event_id in finding.event_ids
        if event_id in events_by_id
    ]
    resolved_events.sort(key=_sort_key)
    unresolved_event_count = len(finding.event_ids) - len(resolved_events)

    involved = [
        entities_by_id[entity_id]
        for entity_id in finding.entity_ids
        if entity_id in entities_by_id
    ]
    involved.sort(key=lambda entity: str(entity.id))
    unresolved_entity_count = len(finding.entity_ids) - len(involved)

    evidence: list[Evidence] = []
    timeline: list[TimelineEntry] = []
    for event in resolved_events:
        evidence.append(
            Evidence(
                id=uuid5(_EVIDENCE_NAMESPACE, str(event.id)),
                collected_at=event.occurred_at,
                description=_evidence_description(
                    event, entities_by_id, finding_scoped_ids
                ),
                relationship=EvidenceRelationship.SUPPORTS,
                source_event_id=event.id,
            )
        )

        entity_ids: list[UUID] = []
        if event.actor_entity_id is not None:
            entity_ids.append(event.actor_entity_id)
        # Preserve the original target IDs (including any shared-service target)
        # so the timeline represents the source event faithfully.
        entity_ids.extend(event.target_entity_ids)
        timeline.append(
            TimelineEntry(
                occurred_at=event.occurred_at,
                event_id=event.id,
                summary=_event_summary(event, entities_by_id, finding_scoped_ids),
                entity_ids=tuple(entity_ids),
            )
        )

    incomplete = bool(
        unresolved_event_count or unresolved_entity_count or not resolved_events
    )

    success_present = any(_is_success(event) for event in resolved_events)
    unresolved_questions = list(_BASE_UNRESOLVED_QUESTIONS)
    unresolved_questions.append(
        _SUCCESS_QUESTION_PRESENT if success_present else _SUCCESS_QUESTION_ABSENT
    )
    if incomplete:
        unresolved_questions.append(_INCOMPLETENESS_QUESTION)

    assessments = list(_ANALYST_ASSESSMENTS)
    if incomplete:
        assessments.append(_INCOMPLETENESS_ASSESSMENT)

    return InvestigationResult(
        finding=finding,
        involved_entities=tuple(involved),
        evidence=tuple(evidence),
        timeline=tuple(timeline),
        confirmed_facts=_confirmed_facts(
            resolved_events,
            involved,
            unresolved_event_count=unresolved_event_count,
            unresolved_entity_count=unresolved_entity_count,
            finding_entity_ids=list(finding.entity_ids),
        ),
        analyst_assessments=tuple(assessments),
        unresolved_questions=tuple(unresolved_questions),
    )
