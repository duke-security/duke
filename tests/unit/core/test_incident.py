"""Tests for the Incident domain model."""

from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from duke.core import Incident, IncidentStatus, Severity


def _build_incident(opened_at: datetime, **overrides: object) -> Incident:
    defaults: dict[str, object] = {
        "opened_at": opened_at,
        "updated_at": opened_at,
        "title": "Suspicious login from unfamiliar location",
        "summary": "A user authenticated from two distant locations quickly.",
        "status": IncidentStatus.INVESTIGATING,
        "severity": Severity.HIGH,
        "finding_ids": [uuid4()],
        "affected_entity_ids": [uuid4()],
    }
    defaults.update(overrides)
    return Incident(**defaults)


def test_valid_incident_construction(aware_now: datetime) -> None:
    incident = _build_incident(aware_now)

    assert incident.status is IncidentStatus.INVESTIGATING
    assert len(incident.finding_ids) == 1
    assert len(incident.affected_entity_ids) == 1


def test_default_id_is_unique(aware_now: datetime) -> None:
    first = _build_incident(aware_now)
    second = _build_incident(aware_now)

    assert first.id != second.id


def test_json_round_trip(aware_now: datetime) -> None:
    incident = _build_incident(aware_now, evidence_ids=[uuid4()])

    restored = Incident.model_validate_json(incident.model_dump_json())

    assert restored == incident


def test_invalid_status_rejected(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_incident(aware_now, status="not-a-status")


def test_naive_datetime_rejected(naive_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_incident(naive_now)


def test_unknown_field_rejected(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_incident(aware_now, owner="soc-team")


def test_requires_at_least_one_finding(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_incident(aware_now, finding_ids=[])


def test_requires_at_least_one_affected_entity(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_incident(aware_now, affected_entity_ids=[])
