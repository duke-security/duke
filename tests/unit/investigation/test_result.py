"""Tests for typed investigation results."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from duke.core import (
    Entity,
    EntityType,
    Evidence,
    EvidenceRelationship,
    Finding,
    FindingStatus,
    Severity,
)
from duke.investigation import InvestigationResult, TimelineEntry

AWARE_TIME = datetime(2026, 9, 22, 8, 1, tzinfo=UTC)


def _build_result() -> InvestigationResult:
    event_id = uuid4()
    entity = Entity(
        entity_type=EntityType.ACCOUNT,
        identifier="alex.morgan@example.lab",
    )
    finding = Finding(
        created_at=AWARE_TIME,
        confidence=90,
        title="Suspicious valid-account activity",
        description="A suspicious sequence was detected.",
        detection_name="compromised-identity-sequence",
        detection_details="Confidence 90/100.",
        technique_id="T1078",
        severity=Severity.HIGH,
        status=FindingStatus.NEW,
        event_ids=[event_id],
        entity_ids=[entity.id],
    )
    evidence = Evidence(
        collected_at=AWARE_TIME,
        description="A successful login occurred from unfamiliar context.",
        relationship=EvidenceRelationship.SUPPORTS,
        source_event_id=event_id,
    )
    timeline_entry = TimelineEntry(
        occurred_at=AWARE_TIME,
        event_id=event_id,
        summary="Successful authentication from unfamiliar context.",
        entity_ids=(entity.id,),
    )

    return InvestigationResult(
        finding=finding,
        involved_entities=(entity,),
        evidence=(evidence,),
        timeline=(timeline_entry,),
        confirmed_facts=("The account authenticated successfully.",),
        analyst_assessments=(
            "The activity is consistent with possible valid-account misuse.",
        ),
        unresolved_questions=("Was the login performed by the account owner?",),
    )


def test_valid_investigation_result() -> None:
    result = _build_result()

    assert result.finding.technique_id == "T1078"
    assert len(result.evidence) == 1
    assert len(result.timeline) == 1
    assert len(result.confirmed_facts) == 1
    assert len(result.analyst_assessments) == 1
    assert len(result.unresolved_questions) == 1


def test_json_round_trip() -> None:
    result = _build_result()

    restored = InvestigationResult.model_validate_json(result.model_dump_json())

    assert restored == result


def test_timeline_rejects_naive_datetime() -> None:
    with pytest.raises(ValidationError):
        TimelineEntry(
            occurred_at=datetime(2026, 9, 22, 8, 1),
            event_id=uuid4(),
            summary="Naive timestamps are unsafe.",
        )


def test_timeline_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        TimelineEntry(
            occurred_at=AWARE_TIME,
            event_id=uuid4(),
            summary="Known event.",
            vendor_name="example",
        )
