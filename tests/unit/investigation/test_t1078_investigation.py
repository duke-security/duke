"""Tests for the evidence-led T1078 investigation."""

from datetime import UTC, datetime
from uuid import uuid4

from duke.core import (
    Evidence,
    EvidenceRelationship,
    Finding,
    FindingStatus,
    Severity,
)
from duke.detection import detect_t1078
from duke.investigation import investigate_t1078
from duke.simulation import generate_t1078_simulation
from duke.telemetry import TelemetryArtefact


def _artefact() -> TelemetryArtefact:
    result = generate_t1078_simulation()
    return TelemetryArtefact(entities=result.entities, events=result.events)


def test_evidence_covers_only_referenced_events() -> None:
    artefact = _artefact()
    finding = detect_t1078(artefact.events)[0]

    result = investigate_t1078(artefact, finding)

    assert len(result.evidence) == len(finding.event_ids) == 7
    source_ids = {evidence.source_event_id for evidence in result.evidence}
    assert source_ids == set(finding.event_ids)


def test_evidence_relationships_are_classified() -> None:
    artefact = _artefact()
    finding = detect_t1078(artefact.events)[0]
    events_by_id = {event.id: event for event in artefact.events}

    result = investigate_t1078(artefact, finding)

    baseline: list[Evidence] = []
    supports: list[Evidence] = []
    for evidence in result.evidence:
        assert evidence.source_event_id is not None
        event = events_by_id[evidence.source_event_id]
        if event.attributes.get("network_context") == "known":
            baseline.append(evidence)
        else:
            supports.append(evidence)

    assert len(baseline) == 1
    assert baseline[0].relationship is EvidenceRelationship.PROVIDES_CONTEXT
    assert supports
    assert all(
        evidence.relationship is EvidenceRelationship.SUPPORTS
        for evidence in supports
    )


def test_timeline_is_chronological() -> None:
    artefact = _artefact()
    finding = detect_t1078(artefact.events)[0]

    result = investigate_t1078(artefact, finding)

    timestamps = [entry.occurred_at for entry in result.timeline]
    assert timestamps == sorted(timestamps)
    assert timestamps[0].minute == 0  # the known-good baseline is first
    assert {entry.event_id for entry in result.timeline} == set(finding.event_ids)


def test_involved_entities_resolve_from_artefact() -> None:
    artefact = _artefact()
    finding = detect_t1078(artefact.events)[0]
    identifiers = {entity.identifier for entity in artefact.entities}

    result = investigate_t1078(artefact, finding)

    involved = {entity.identifier for entity in result.involved_entities}
    assert involved <= identifiers
    assert "alex.morgan@example.lab" in involved
    assert "device-unknown-442" in involved
    # The known-good baseline device stays contextual, not involved.
    assert "workstation-017" not in involved


def test_output_is_deterministic() -> None:
    artefact = _artefact()
    finding = detect_t1078(artefact.events)[0]

    first = investigate_t1078(artefact, finding)
    second = investigate_t1078(artefact, finding)

    assert first == second
    assert first.evidence == second.evidence


def test_facts_assessments_questions_are_populated() -> None:
    artefact = _artefact()
    finding = detect_t1078(artefact.events)[0]

    result = investigate_t1078(artefact, finding)

    assert result.confirmed_facts
    assert result.analyst_assessments
    assert result.unresolved_questions
    # Facts, assessments, and open questions are kept distinct.
    assert not set(result.confirmed_facts) & set(result.analyst_assessments)
    assert not set(result.analyst_assessments) & set(result.unresolved_questions)


def test_finding_with_no_referenced_events_is_graceful() -> None:
    artefact = _artefact()
    empty_finding = Finding(
        created_at=datetime(2026, 9, 22, 8, 0, tzinfo=UTC),
        confidence=60,
        title="Empty finding",
        description="A finding with no referenced events.",
        detection_name="test-rule",
        detection_details="No events.",
        technique_id="T1078",
        severity=Severity.MEDIUM,
        status=FindingStatus.NEW,
    )

    result = investigate_t1078(artefact, empty_finding)

    assert result.evidence == ()
    assert result.timeline == ()
    assert result.finding is empty_finding


def test_unknown_entity_ids_are_skipped() -> None:
    artefact = _artefact()
    finding = detect_t1078(artefact.events)[0]
    # An implicated entity identifier that does not exist in the artefact.
    finding.entity_ids.append(uuid4())

    result = investigate_t1078(artefact, finding)

    involved_ids = {entity.id for entity in result.involved_entities}
    assert involved_ids <= {entity.id for entity in artefact.entities}
