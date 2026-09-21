"""Tests for the ResponseAction domain model."""

from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from duke.core import ResponseAction, ResponseRisk, ResponseStatus


def _build_response_action(created_at: datetime, **overrides: object) -> ResponseAction:
    defaults: dict[str, object] = {
        "created_at": created_at,
        "incident_id": uuid4(),
        "name": "disable-compromised-account",
        "purpose": "Prevent further use of a likely-compromised account.",
        "risk": ResponseRisk.MEDIUM,
        "requires_approval": True,
        "dry_run": True,
        "status": ResponseStatus.PLANNED,
        "verification_guidance": "Confirm the account can no longer authenticate.",
        "supports_rollback": True,
        "rollback_guidance": "Re-enable the account via the identity provider.",
    }
    defaults.update(overrides)
    return ResponseAction(**defaults)


def test_valid_response_action_construction(aware_now: datetime) -> None:
    action = _build_response_action(aware_now)

    assert action.risk is ResponseRisk.MEDIUM
    assert action.status is ResponseStatus.PLANNED
    assert action.dry_run is True


def test_default_id_is_unique(aware_now: datetime) -> None:
    first = _build_response_action(aware_now)
    second = _build_response_action(aware_now)

    assert first.id != second.id


def test_json_round_trip(aware_now: datetime) -> None:
    action = _build_response_action(aware_now, target_entity_id=uuid4())

    restored = ResponseAction.model_validate_json(action.model_dump_json())

    assert restored == action


def test_invalid_risk_rejected(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_response_action(aware_now, risk="extreme")


def test_naive_datetime_rejected(naive_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_response_action(naive_now)


def test_unknown_field_rejected(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_response_action(aware_now, automated=True)


def test_incident_relationship_is_required(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_response_action(aware_now, incident_id=None)


def test_rollback_guidance_required_when_supported(aware_now: datetime) -> None:
    with pytest.raises(ValidationError):
        _build_response_action(
            aware_now, supports_rollback=True, rollback_guidance=None
        )


def test_rollback_guidance_optional_when_not_supported(aware_now: datetime) -> None:
    action = _build_response_action(
        aware_now, supports_rollback=False, rollback_guidance=None
    )

    assert action.rollback_guidance is None
