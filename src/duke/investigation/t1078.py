"""Evidence-led investigation for the T1078 Valid Accounts scenario.

Investigation does not run detection itself. ``investigate_t1078``
consumes an existing ``Finding`` produced by detection and turns it, plus
the normalized telemetry it references, into an evidence-led
``InvestigationResult``: a chronological timeline, one ``Evidence`` per
referenced event, the involved entities, and distinct confirmed facts,
analyst assessments, and unresolved questions.

This keeps ``investigation`` separate from ``detection``: the caller
(``duke investigate``) loads the artefact, runs ``detect_t1078``, and
passes the finding in. See ``docs/investigations/T1078-compromised-identity.md``.
"""

from uuid import UUID, uuid5

from duke.core import (
    Entity,
    Evidence,
    EvidenceRelationship,
    Finding,
    SecurityEvent,
)
from duke.investigation.result import InvestigationResult, TimelineEntry
from duke.telemetry import TelemetryArtefact

# Deterministic namespace so evidence identifiers are repeatable for the
# same referenced event, mirroring the stable IDs used by simulation and
# detection.
_EVIDENCE_NAMESPACE = UUID("10786000-0000-4000-8000-000000000000")


def _is_known_good_auth(event: SecurityEvent) -> bool:
    """Return whether an event is a successful login from known context."""
    return (
        event.action == "authenticate"
        and event.attributes.get("network_context") == "known"
        and event.attributes.get("device_context") == "known"
    )


def _event_summary(event: SecurityEvent) -> str:
    """A short human-readable summary for one referenced event."""
    if _is_known_good_auth(event):
        return "Successful authentication from a known network and device"
    if event.action == "authenticate":
        return "Successful authentication from a new network and unfamiliar device"

    summaries = {
        "access_application": "Application access",
        "enumerate_repository": "Repository enumeration",
        "read_file": "Restricted file access",
        "request_privileged_access": "Privileged-access request",
        "create_archive": "Archive creation",
        "network_connect": "Outbound network connection",
    }
    return summaries.get(event.action, event.action.replace("_", " ").capitalize())


def _evidence_description(event: SecurityEvent) -> str:
    """What a piece of evidence shows and why it matters."""
    if _is_known_good_auth(event):
        return (
            "Baseline context: the account authenticated successfully from a "
            "known network and device before the suspicious activity."
        )
    if event.action == "authenticate":
        return (
            "The account authenticated successfully from a new network and "
            "unfamiliar device, anchoring the suspicious sequence."
        )
    return f"{_event_summary(event)} by the implicated identity."


def _confirmed_facts(ordered_events: list[SecurityEvent]) -> tuple[str, ...]:
    """Distinct, evidence-grounded facts derived from referenced events."""
    facts: list[str] = []
    if any(_is_known_good_auth(e) for e in ordered_events):
        facts.append(
            "The account authenticated successfully from a known network and device."
        )
    if any(
        e.action == "authenticate" and not _is_known_good_auth(e)
        for e in ordered_events
    ):
        facts.append(
            "The account authenticated successfully from a new network and "
            "unfamiliar device."
        )
    if any(e.action == "enumerate_repository" for e in ordered_events):
        facts.append("Repository content was enumerated.")
    if any(
        e.action == "read_file"
        and e.attributes.get("data_classification") == "restricted"
        for e in ordered_events
    ):
        facts.append("A restricted file was accessed.")
    if any(e.action == "request_privileged_access" for e in ordered_events):
        facts.append("A privileged-access request was made.")
    if any(e.action == "create_archive" for e in ordered_events):
        facts.append("An archive was created.")
    if any(e.action == "network_connect" for e in ordered_events):
        facts.append("An outbound network connection was observed.")
    return tuple(facts)


_ANALYST_ASSESSMENTS = (
    "The new-context login followed by a correlated set of behaviours is "
    "consistent with possible valid-account misuse (MITRE ATT&CK T1078).",
    "This is a behavioural signal; impact, exfiltration, and account "
    "compromise are not confirmed by investigation alone.",
)

_UNRESOLVED_QUESTIONS = (
    "Did the account owner perform the new-context login and follow-on behaviours?",
    "Was any restricted file or archive exfiltrated during the session?",
    "Was the requested privileged access granted, and did it persist?",
)


def investigate_t1078(
    artefact: TelemetryArtefact,
    finding: Finding,
) -> InvestigationResult:
    """Build an evidence-led ``InvestigationResult`` from an existing finding.

    Only the events referenced by ``finding.event_ids`` are considered.
    The known-good baseline authentication is recorded as context
    (``PROVIDES_CONTEXT``); the new-context authentication and any
    follow-on behaviours support the finding (``SUPPORTS``). The timeline
    lists those referenced events chronologically.
    """
    events_by_id = {event.id: event for event in artefact.events}
    referenced = [
        events_by_id[event_id]
        for event_id in finding.event_ids
        if event_id in events_by_id
    ]
    ordered_events = sorted(referenced, key=lambda event: event.occurred_at)

    evidence: list[Evidence] = []
    timeline: list[TimelineEntry] = []
    for event in ordered_events:
        is_baseline = _is_known_good_auth(event)
        evidence.append(
            Evidence(
                id=uuid5(_EVIDENCE_NAMESPACE, str(event.id)),
                collected_at=event.occurred_at,
                description=_evidence_description(event),
                relationship=(
                    EvidenceRelationship.PROVIDES_CONTEXT
                    if is_baseline
                    else EvidenceRelationship.SUPPORTS
                ),
                source_event_id=event.id,
            )
        )

        entity_ids: list[UUID] = []
        if event.actor_entity_id is not None:
            entity_ids.append(event.actor_entity_id)
        entity_ids.extend(event.target_entity_ids)
        timeline.append(
            TimelineEntry(
                occurred_at=event.occurred_at,
                event_id=event.id,
                summary=_event_summary(event),
                entity_ids=tuple(entity_ids),
            )
        )

    entities_by_id = {entity.id: entity for entity in artefact.entities}
    involved_entities: tuple[Entity, ...] = tuple(
        entities_by_id[entity_id]
        for entity_id in finding.entity_ids
        if entity_id in entities_by_id
    )

    return InvestigationResult(
        finding=finding,
        involved_entities=involved_entities,
        evidence=tuple(evidence),
        timeline=tuple(timeline),
        confirmed_facts=_confirmed_facts(ordered_events),
        analyst_assessments=_ANALYST_ASSESSMENTS,
        unresolved_questions=_UNRESOLVED_QUESTIONS,
    )
