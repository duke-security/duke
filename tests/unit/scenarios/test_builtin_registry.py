"""Tests for the built-in T1078 scenario registration."""

import pytest

from duke.core import Scenario
from duke.detection import detect_t1078
from duke.investigation import investigate_t1078
from duke.learning import t1078_learning_path
from duke.reporting import report_t1078
from duke.response import plan_t1078_response
from duke.scenarios import ScenarioCapability, UnknownScenarioError, has_capability
from duke.scenarios.builtins import (
    builtin_registry,
    load_t1078_metadata,
    t1078_registration,
)
from duke.simulation import generate_t1078_simulation
from duke.validation import validate_t1078


def test_all_seven_capabilities_are_the_real_functions() -> None:
    reg = t1078_registration()
    assert reg.capabilities.simulation is generate_t1078_simulation
    assert reg.capabilities.detection is detect_t1078
    assert reg.capabilities.investigation is investigate_t1078
    assert reg.capabilities.response is plan_t1078_response
    assert reg.capabilities.validation is validate_t1078
    assert reg.capabilities.reporting is report_t1078
    assert reg.capabilities.learning is t1078_learning_path


def test_registration_core_metadata() -> None:
    reg = t1078_registration()
    assert reg.technique_id == "T1078"
    assert reg.slug == "t1078_valid_accounts"
    assert reg.name == "Valid Accounts: Compromised Identity"
    assert reg.aliases == ("valid-accounts",)


def test_builtin_resolution_forms_resolve_to_same_registration() -> None:
    registry = builtin_registry()
    canonical = registry.resolve("T1078")
    assert registry.resolve("t1078") is canonical
    assert registry.resolve("t1078_valid_accounts") is canonical
    assert registry.resolve("valid-accounts") is canonical


def test_builtin_unknown_scenario_raises() -> None:
    registry = builtin_registry()
    with pytest.raises(UnknownScenarioError):
        registry.resolve("T9999")
    with pytest.raises(UnknownScenarioError):
        registry.resolve("not-a-registered-key")


def test_every_capability_is_available() -> None:
    reg = t1078_registration()
    for capability in ScenarioCapability:
        assert has_capability(reg, capability), capability


def test_builtin_listing_is_deterministic() -> None:
    registry = builtin_registry()
    assert [r.technique_id for r in registry.scenarios()] == ["T1078", "T1110"]


def test_display_metadata_agrees_with_yaml_metadata() -> None:
    reg = t1078_registration()
    meta = load_t1078_metadata()

    assert isinstance(meta, Scenario)
    assert reg.name == meta.name
    assert reg.technique_id == meta.attack_technique_id


def test_metadata_loader_is_lazy(monkeypatch) -> None:
    calls: list[str] = []

    def spy():
        calls.append("loader")
        return load_t1078_metadata()

    monkeypatch.setattr("duke.scenarios.builtins.load_t1078_metadata", spy)
    registry = builtin_registry()

    # Building, resolving, and listing must not invoke the loader.
    registry.resolve("T1078")
    registry.resolve("valid-accounts")
    registry.scenarios()
    assert calls == []

    # Invoking the loader explicitly is what loads the metadata.
    meta = registry.resolve("T1078").metadata_loader()
    assert meta.attack_technique_id == "T1078"
    assert calls == ["loader"]
