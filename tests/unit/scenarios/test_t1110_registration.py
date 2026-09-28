"""Tests for the T1110.003 brute-force scenario registration."""

import pytest

from duke.core import Scenario
from duke.detection import detect_t1110
from duke.investigation import investigate_t1110
from duke.reporting import report_t1110
from duke.response import plan_t1110_response
from duke.scenarios import ScenarioCapability, UnknownScenarioError, has_capability
from duke.scenarios.builtins import (
    builtin_registry,
    load_t1110_metadata,
    t1110_registration,
)
from duke.simulation import generate_t1110_simulation
from duke.validation import validate_t1110


def test_registration_core_metadata() -> None:
    reg = t1110_registration()
    assert reg.technique_id == "T1110"
    assert reg.slug == "t1110_brute_force"
    assert reg.name == "Brute Force: Password Spraying"
    assert reg.aliases == ("brute-force", "T1110.003")


def test_registration_provides_lifecycle_through_reporting() -> None:
    """This slice provides simulation through reporting; learning remains
    intentionally unimplemented."""
    reg = t1110_registration()
    assert has_capability(reg, ScenarioCapability.SIMULATION)
    assert reg.capabilities.simulation is generate_t1110_simulation
    assert has_capability(reg, ScenarioCapability.DETECTION)
    assert reg.capabilities.detection is detect_t1110
    assert has_capability(reg, ScenarioCapability.INVESTIGATION)
    assert reg.capabilities.investigation is investigate_t1110
    assert has_capability(reg, ScenarioCapability.RESPONSE)
    assert reg.capabilities.response is plan_t1110_response
    assert has_capability(reg, ScenarioCapability.VALIDATION)
    assert reg.capabilities.validation is validate_t1110
    assert has_capability(reg, ScenarioCapability.REPORTING)
    assert reg.capabilities.reporting is report_t1110
    assert not has_capability(reg, ScenarioCapability.LEARNING)


def test_builtin_resolution_forms_resolve_to_same_registration() -> None:
    registry = builtin_registry()
    canonical = registry.resolve("T1110")
    assert registry.resolve("t1110") is canonical  # case-insensitive
    assert registry.resolve("t1110_brute_force") is canonical  # slug
    assert registry.resolve("brute-force") is canonical  # friendly alias
    assert registry.resolve("T1110.003") is canonical  # sub-technique


def test_builtin_unknown_scenario_raises() -> None:
    registry = builtin_registry()
    with pytest.raises(UnknownScenarioError):
        registry.resolve("T9999")
    with pytest.raises(UnknownScenarioError):
        registry.resolve("not-a-registered-key")


def test_builtin_registry_contains_both_scenarios() -> None:
    registry = builtin_registry()
    registry.resolve("T1078")
    registry.resolve("T1110")


def test_display_metadata_agrees_with_yaml_metadata() -> None:
    reg = t1110_registration()
    meta = load_t1110_metadata()

    assert isinstance(meta, Scenario)
    assert reg.name == meta.name
    assert reg.technique_id == meta.attack_technique_id
    assert "Credential Access" in meta.attack_tactics


def test_t1110_is_registered_second_and_deterministic() -> None:
    registry = builtin_registry()
    assert [r.technique_id for r in registry.scenarios()] == ["T1078", "T1110"]
