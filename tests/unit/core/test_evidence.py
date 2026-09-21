"""Tests for the Evidence domain model."""

from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from duke.core import Evidence, EvidenceRelationship


def _build_evidence(collected_at: datetime, **overrides: object) -> Evidence:
    defaults: dict[str, object] = {
        "collected_at": collected_at,
        "description": "Login succeeded from an unfamiliar country.",
        "relationship": EvidenceRelationship.SUPPORTS,
        "source_artifact_reference": "hash:abc123",
    }
    defaults.update(overrides)
    return Evidence(**defaults)


def test_valid_evidence_construction(aware_now: datetime) -> None:
    event_id = uuid4()
    evidence = _build_evidence(
        aware_now, source_artifact_reference=None, source_event_id=event_id
    )

    assert evidence.relationship is EvidenceRelationship.SUPPORTS
    assert evidence.source_event_id == event_id


def test_default_id_is_unique(aware_now: datetime) -> None:
    first = _build_evidence(aware_now)
    second = _build_evidence(aware_now)

    assert first.id != second.id


def test_json_round_trip(aware_now: datetime) -> None:
    evidence = _build_evidence(aware_now, relationship=EvidenceRelationship.CONTRADICTS)

    restored = Evidence.model_validate_json(evidence.model_dump_json())

    assert restored == evidence


def test_invalid_relationship_rejected(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_evidence(aware_now, relationship="maybe")


def test_naive_datetime_rejected(naive_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_evidence(naive_now)


def test_unknown_field_rejected(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_evidence(aware_now, confidence=0.9)


def test_requires_a_source(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_evidence(aware_now, source_artifact_reference=None)
