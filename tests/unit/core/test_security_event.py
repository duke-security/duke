"""Tests for the SecurityEvent domain model."""

from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from duke.core import EventOutcome, SecurityEvent


def _build_event(occurred_at: datetime, **overrides: object) -> SecurityEvent:
    defaults: dict[str, object] = {
        "occurred_at": occurred_at,
        "action": "authenticate",
        "outcome": EventOutcome.SUCCESS,
        "source": "identity_provider",
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)


def test_valid_security_event_construction(aware_now: datetime) -> None:
    event = _build_event(aware_now, attributes={"mfa_used": "true"})

    assert event.action == "authenticate"
    assert event.outcome is EventOutcome.SUCCESS
    assert event.target_entity_ids == []
    assert event.attributes == {"mfa_used": "true"}


def test_default_id_is_unique(aware_now: datetime) -> None:
    first = _build_event(aware_now)
    second = _build_event(aware_now)

    assert first.id != second.id


def test_json_round_trip(aware_now: datetime) -> None:
    event = _build_event(aware_now, outcome=EventOutcome.FAILURE)

    restored = SecurityEvent.model_validate_json(event.model_dump_json())

    assert restored == event


def test_invalid_outcome_rejected(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_event(aware_now, outcome="maybe")


def test_naive_datetime_rejected(naive_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_event(naive_now)


def test_unknown_field_rejected(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_event(aware_now, cloud_provider="aws")


def test_actor_and_target_entity_relationship(aware_now: datetime) -> None:
    actor_id = uuid4()
    target_id = uuid4()

    event = _build_event(
        aware_now, actor_entity_id=actor_id, target_entity_ids=[target_id]
    )

    assert event.actor_entity_id == actor_id
    assert target_id in event.target_entity_ids
