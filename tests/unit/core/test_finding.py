"""Tests for the Finding domain model."""

from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from duke.core import Finding, FindingStatus, Severity


def _build_finding(created_at: datetime, **overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "created_at": created_at,
        "title": "Impossible travel login",
        "description": "A user authenticated from two distant locations quickly.",
        "detection_name": "impossible-travel",
        "detection_details": "Two successful logins 6000km apart within 10 minutes.",
        "severity": Severity.HIGH,
        "status": FindingStatus.NEW,
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_valid_finding_construction(aware_now: datetime) -> None:
    finding = _build_finding(aware_now)

    assert finding.severity is Severity.HIGH
    assert finding.status is FindingStatus.NEW
    assert finding.event_ids == []


def test_default_id_is_unique(aware_now: datetime) -> None:
    first = _build_finding(aware_now)
    second = _build_finding(aware_now)

    assert first.id != second.id


def test_json_round_trip(aware_now: datetime) -> None:
    finding = _build_finding(aware_now, technique_id="T1078", event_ids=[uuid4()])

    restored = Finding.model_validate_json(finding.model_dump_json())

    assert restored == finding


def test_invalid_status_rejected(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_finding(aware_now, status="not-a-status")


def test_naive_datetime_rejected(naive_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_finding(naive_now)


def test_unknown_field_rejected(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_finding(aware_now, confidence_score=0.95)


def test_supporting_evidence_and_event_relationships(aware_now: datetime) -> None:
    event_id, evidence_id, entity_id = uuid4(), uuid4(), uuid4()

    finding = _build_finding(
        aware_now,
        event_ids=[event_id],
        evidence_ids=[evidence_id],
        entity_ids=[entity_id],
    )

    assert finding.event_ids == [event_id]
    assert finding.evidence_ids == [evidence_id]
    assert finding.entity_ids == [entity_id]
