"""Tests for the Scenario domain model."""

from datetime import date

import pytest
from pydantic import ValidationError

from duke.core import Scenario


def _build_scenario(**overrides: object) -> Scenario:
    defaults: dict[str, object] = {
        "name": "Valid Accounts: Anomalous Authentication",
        "description": "Detect and investigate use of compromised valid credentials.",
        "attack_technique_id": "T1078",
        "attack_tactic": "Initial Access",
        "learning_objectives": ["Recognize impossible-travel authentication patterns."],
        "python_concepts": ["dataclasses", "datetime arithmetic"],
        "telemetry_requirements": ["Normalized authentication events."],
        "safety_notes": ["Uses synthetic accounts and synthetic IP geolocation only."],
        "version": "1.0.0",
        "last_reviewed": date(2026, 1, 1),
    }
    defaults.update(overrides)
    return Scenario(**defaults)


def test_valid_scenario_construction() -> None:
    scenario = _build_scenario()

    assert scenario.attack_technique_id == "T1078"
    assert scenario.last_reviewed == date(2026, 1, 1)


def test_default_id_is_unique() -> None:
    first = _build_scenario()
    second = _build_scenario()

    assert first.id != second.id


def test_json_round_trip() -> None:
    scenario = _build_scenario()

    restored = Scenario.model_validate_json(scenario.model_dump_json())

    assert restored == scenario


def test_unknown_field_rejected() -> None:
    with pytest.raises(ValidationError):
        _build_scenario(cloud_provider="aws")


def test_requires_at_least_one_learning_objective() -> None:
    with pytest.raises(ValidationError):
        _build_scenario(learning_objectives=[])


def test_requires_at_least_one_safety_note() -> None:
    with pytest.raises(ValidationError):
        _build_scenario(safety_notes=[])
