"""Tests for the evidence-led T1110 password-spraying investigation."""

from datetime import UTC, datetime
from uuid import uuid4

from duke.core import (
    Entity,
    EvidenceRelationship,
    Finding,
    FindingStatus,
    Severity,
)
from duke.detection import detect_t1110
from duke.investigation import investigate_t1110
from duke.investigation.t1110 import (
    _INCOMPLETENESS_ASSESSMENT,
    _INCOMPLETENESS_QUESTION,
)
from duke.simulation import generate_t1110_simulation
from duke.telemetry import TelemetryArtefact

SPRAY_NAME = "password-spraying-window"
SPRAY_TECHNIQUE = "T1110"

PORTAL_IDENTIFIER = "web-portal"
SOURCE_IDENTIFIER = "host-198.51.100.77"
SPRAYED_ACCOUNTS = (
    "svc.integration",
    "svc.reports",
    "svc.analytics",
    "svc.etl",
    "d.garcia",
    "a.okafor",
)


def _artefact() -> TelemetryArtefact:
    result = generate_t1110_simulation()
    return TelemetryArtefact(entities=result.entities, events=result.events)


def _finding(artefact: TelemetryArtefact) -> Finding:
    return detect_t1110(artefact.events)[0]


def _identifiers(entities: list[Entity]) -> set[str]:
    return {entity.identifier for entity in entities}


# ---- evidence scoping & classification --------------------------------------


def test_evidence_covers_only_referenced_events() -> None:
    artefact = _artefact()
    finding = _finding(artefact)

    result = investigate_t1110(artefact, finding)

    assert len(result.evidence) == len(finding.event_ids) == 7
    source_ids = {evidence.source_event_id for evidence in result.evidence}
    assert source_ids == set(finding.event_ids)


def test_all_evidence_supports_the_finding() -> None:
    """Every referenced T1110 event is a spray failure or the credited success;
    all are supporting (no separate baseline/context event exists)."""
    artefact = _artefact()
    finding = _finding(artefact)

    result = investigate_t1110(artefact, finding)

    assert result.evidence
    assert all(
        evidence.relationship is EvidenceRelationship.SUPPORTS
        for evidence in result.evidence
    )


def test_evidence_does_not_name_the_portal_as_an_account() -> None:
    """Evidence descriptions name only finding-scoped account targets, never
    the shared authentication service."""
    artefact = _artefact()
    finding = _finding(artefact)

    result = investigate_t1110(artefact, finding)

    text = " ".join(evidence.description for evidence in result.evidence).lower()
    assert "web-portal" not in text
    # The success is described as supporting evidence, not proof.
    assert "credential may have validated" in text or "supporting evidence" in text


# ---- timeline ---------------------------------------------------------------


def test_timeline_is_chronological_and_faithful() -> None:
    artefact = _artefact()
    finding = _finding(artefact)

    result = investigate_t1110(artefact, finding)

    timestamps = [entry.occurred_at for entry in result.timeline]
    assert timestamps == sorted(timestamps)
    assert {entry.event_id for entry in result.timeline} == set(finding.event_ids)


def test_timeline_preserves_original_target_ids_including_portal() -> None:
    """The timeline represents each source event faithfully, so a shared
    service target appears in a timeline entry — but the portal is never in
    the investigation's headline involved_entities."""
    artefact = _artefact()
    finding = _finding(artefact)
    portal_id = next(
        e.id for e in artefact.entities if e.identifier == PORTAL_IDENTIFIER
    )

    result = investigate_t1110(artefact, finding)

    # Portal appears in the raw timeline entry target IDs.
    assert any(
        portal_id in entry.entity_ids for entry in result.timeline
    )
    # Portal is never an involved_entity.
    involved = _identifiers(list(result.involved_entities))
    assert PORTAL_IDENTIFIER not in involved


# ---- involved entities ------------------------------------------------------


def test_involved_entities_are_source_and_accounts_only() -> None:
    artefact = _artefact()
    finding = _finding(artefact)

    result = investigate_t1110(artefact, finding)

    involved = _identifiers(list(result.involved_entities))
    assert involved <= {entity.identifier for entity in artefact.entities}
    assert SOURCE_IDENTIFIER in involved
    for account in SPRAYED_ACCOUNTS:
        assert account in involved
    # The shared service is context, not implicated.
    assert PORTAL_IDENTIFIER not in involved


# ---- confirmed facts / assessments / questions ------------------------------


def test_facts_assessments_questions_are_populated_and_distinct() -> None:
    artefact = _artefact()
    finding = _finding(artefact)

    result = investigate_t1110(artefact, finding)

    assert result.confirmed_facts
    assert result.analyst_assessments
    assert result.unresolved_questions
    assert not set(result.confirmed_facts) & set(result.analyst_assessments)
    assert not set(result.analyst_assessments) & set(result.unresolved_questions)


def test_facts_distinguish_failures_targets_and_unresolved() -> None:
    artefact = _artefact()
    finding = _finding(artefact)

    result = investigate_t1110(artefact, finding)

    facts = " ".join(result.confirmed_facts)
    assert "6 failed authentications" in facts
    assert "implicated target entities were resolved" in facts
    # No unresolved references in the complete corpus.
    assert "could not be resolved" not in facts


def test_success_aware_questions() -> None:
    """The success-related unresolved question is worded according to whether
    a later success is referenced."""
    artefact = _artefact()
    finding = _finding(artefact)
    result = investigate_t1110(artefact, finding)
    assert any(
        question.startswith("Was the successful authentication")
        for question in result.unresolved_questions
    )


def test_no_compromise_or_attribution_claims() -> None:
    artefact = _artefact()
    finding = _finding(artefact)

    result = investigate_t1110(artefact, finding)
    text = " ".join(
        [
            *result.confirmed_facts,
            *result.analyst_assessments,
            *result.unresolved_questions,
        ]
    ).lower()

    for affirmative in (
        "is compromised",
        "has been compromised",
        "is an attacker",
        "is malicious",
        "stole credentials",
        "caused impact",
        "intrusion succeeded",
    ):
        assert affirmative not in text, f"overclaim present: {affirmative!r}"


# ---- missing-reference handling (correction 1) ------------------------------


def test_missing_referenced_event_is_handled_visibly() -> None:
    artefact = _artefact()
    finding = _finding(artefact)
    missing = uuid4()
    finding.event_ids.append(missing)

    result = investigate_t1110(artefact, finding)

    # The missing event does not become evidence/timeline, and nothing is
    # substituted from the unrelated artefact.
    assert missing not in {e.source_event_id for e in result.evidence}
    assert missing not in {t.event_id for t in result.timeline}
    # A deterministic incompleteness question/assessment is added.
    assert any(
        _INCOMPLETENESS_QUESTION in q for q in result.unresolved_questions
    )
    assert any(
        _INCOMPLETENESS_ASSESSMENT in a for a in result.analyst_assessments
    )
    # Facts report the unresolved reference without inventing evidence.
    assert any("could not be resolved" in f for f in result.confirmed_facts)


def test_missing_referenced_entity_is_handled_visibly() -> None:
    artefact = _artefact()
    finding = _finding(artefact)
    missing = uuid4()
    finding.entity_ids.append(missing)

    result = investigate_t1110(artefact, finding)

    assert all(
        entity.id != missing for entity in result.involved_entities
    )
    assert any(
        _INCOMPLETENESS_QUESTION in q for q in result.unresolved_questions
    )
    assert any(
        "could not be resolved" in f for f in result.confirmed_facts
    )


def test_unrelated_artefact_events_are_never_substituted() -> None:
    """Events not referenced by the finding must not leak into the result."""
    artefact = _artefact()
    finding = _finding(artefact)
    unrelated = next(
        event.id
        for event in artefact.events
        if event.id not in finding.event_ids
    )

    result = investigate_t1110(artefact, finding)

    assert unrelated not in {e.source_event_id for e in result.evidence}
    assert unrelated not in {t.event_id for t in result.timeline}


# ---- empty / fully unresolved (correction: no failure) ----------------------


def test_empty_event_ids_yields_empty_evidence_with_incompleteness() -> None:
    artefact = _artefact()
    empty_finding = Finding(
        created_at=datetime(2026, 9, 25, 12, 0, tzinfo=UTC),
        confidence=60,
        title="Empty finding",
        description="A finding with no referenced events.",
        detection_name="test-rule",
        detection_details="No events.",
        technique_id=SPRAY_TECHNIQUE,
        severity=Severity.MEDIUM,
        status=FindingStatus.NEW,
    )

    result = investigate_t1110(artefact, empty_finding)

    assert result.evidence == ()
    assert result.timeline == ()
    assert result.finding is empty_finding
    assert any(
        _INCOMPLETENESS_QUESTION in q for q in result.unresolved_questions
    )


def test_fully_unresolved_event_ids_do_not_fail() -> None:
    artefact = _artefact()
    finding = _finding(artefact)
    finding.event_ids = [uuid4(), uuid4()]  # nothing resolves

    result = investigate_t1110(artefact, finding)

    assert result.evidence == ()
    assert result.timeline == ()
    assert any(
        _INCOMPLETENESS_QUESTION in q for q in result.unresolved_questions
    )


# ---- determinism ------------------------------------------------------------


def test_output_is_deterministic() -> None:
    artefact = _artefact()
    finding = _finding(artefact)

    first = investigate_t1110(artefact, finding)
    second = investigate_t1110(artefact, finding)

    assert first == second
    assert first.evidence == second.evidence
    assert len({evidence.id for evidence in first.evidence}) == len(first.evidence)


# ---- time-then-id tie-breaker ------------------------------------------------


def test_timeline_orders_equal_timestamps_by_event_id() -> None:
    """Two referenced events at the same instant are ordered by event ID."""
    artefact = _artefact()
    # Clone two referenced events to the same timestamp via the artefact,
    # keeping them both referenced by the finding, then re-run.
    events = list(artefact.events)
    # Build a synthetic two-event finding with identical timestamps.
    second = events[0].model_copy(
        update={"id": uuid4(), "occurred_at": datetime(2026, 9, 25, 12, 0, tzinfo=UTC)}
    )
    first = events[1].model_copy(
        update={"id": uuid4(), "occurred_at": datetime(2026, 9, 25, 12, 0, tzinfo=UTC)}
    )
    twin_artefact = TelemetryArtefact(
        entities=artefact.entities, events=(first, second)
    )
    twin_finding = Finding(
        created_at=datetime(2026, 9, 25, 12, 0, tzinfo=UTC),
        confidence=60,
        title="Twins",
        description="Two same-time events.",
        detection_name="test-rule",
        detection_details="Same timestamp.",
        technique_id=SPRAY_TECHNIQUE,
        severity=Severity.MEDIUM,
        status=FindingStatus.NEW,
        event_ids=[first.id, second.id],
        entity_ids=[first.actor_entity_id or first.id],
    )

    result = investigate_t1110(twin_artefact, twin_finding)

    # The two timeline entries have the same timestamp; order follows event ID.
    assert len(result.timeline) == 2
    ordered_ids = [entry.event_id for entry in result.timeline]
    assert ordered_ids == sorted(ordered_ids, key=str)
