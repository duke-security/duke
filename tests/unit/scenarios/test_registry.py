"""Tests for the static built-in scenario registry."""

import pytest

from duke.scenarios import (
    CapabilityMissingError,
    DuplicateScenarioError,
    ScenarioCapabilities,
    ScenarioCapability,
    ScenarioRegistration,
    ScenarioRegistrationError,
    ScenarioRegistry,
    UnknownScenarioError,
    has_capability,
    required_capability,
)


def _noop_meta():
    raise AssertionError("metadata_loader must not be invoked")


def _registration(
    technique_id,
    slug,
    name="Scenario",
    aliases=(),
    caps=None,
) -> ScenarioRegistration:
    return ScenarioRegistration(
        technique_id=technique_id,
        slug=slug,
        name=name,
        aliases=tuple(aliases),
        metadata_loader=_noop_meta,
        capabilities=caps or ScenarioCapabilities(),
    )


def test_listing_is_deterministic_by_technique_id() -> None:
    registry = ScenarioRegistry()
    registry.register(_registration("T1080", "c"))
    registry.register(_registration("T1078", "a"))
    registry.register(_registration("T1079", "b"))

    assert [r.technique_id for r in registry.scenarios()] == [
        "T1078",
        "T1079",
        "T1080",
    ]


def test_resolution_is_case_insensitive_and_matches_slug_and_alias() -> None:
    registry = ScenarioRegistry()
    registry.register(
        _registration("T1078", "t1078_valid_accounts", aliases=("valid-accounts",))
    )

    canonical = registry.resolve("T1078")
    assert registry.resolve("t1078") is canonical
    assert registry.resolve("t1078_valid_accounts") is canonical
    assert registry.resolve("valid-accounts") is canonical


def test_lookup_preserves_canonical_display_values() -> None:
    registry = ScenarioRegistry()
    registry.register(_registration("T1078", "t1078"))

    resolved = registry.resolve("t1078")

    assert resolved.technique_id == "T1078"
    assert resolved.slug == "t1078"
    assert resolved.name == "Scenario"


def test_unknown_scenario_raises_typed_error() -> None:
    registry = ScenarioRegistry()
    registry.register(_registration("T1078", "t1078"))

    with pytest.raises(UnknownScenarioError):
        registry.resolve("T9999")
    with pytest.raises(UnknownScenarioError):
        registry.resolve("")
    with pytest.raises(UnknownScenarioError):
        registry.resolve("some alias that does not exist")


def test_duplicate_technique_id_rejected() -> None:
    registry = ScenarioRegistry()
    registry.register(_registration("T1078", "a"))

    with pytest.raises(DuplicateScenarioError):
        registry.register(_registration("t1078", "b"))


def test_duplicate_slug_rejected() -> None:
    registry = ScenarioRegistry()
    registry.register(_registration("T1078", "myslug"))

    with pytest.raises(DuplicateScenarioError):
        registry.register(_registration("T1079", "MYSLUG"))


def test_alias_collision_rejected() -> None:
    registry = ScenarioRegistry()
    registry.register(_registration("T1078", "a", aliases=("friend",)))

    with pytest.raises(DuplicateScenarioError):
        registry.register(_registration("T1079", "b", aliases=("FRIEND",)))


def test_slug_colliding_with_existing_alias_rejected() -> None:
    registry = ScenarioRegistry()
    registry.register(_registration("T1078", "a", aliases=("friend",)))

    with pytest.raises(DuplicateScenarioError):
        registry.register(_registration("T1079", "friend"))


def test_registration_rejects_empty_metadata() -> None:
    with pytest.raises(ScenarioRegistrationError):
        _registration("", "slug")
    with pytest.raises(ScenarioRegistrationError):
        _registration("T1078", "")
    with pytest.raises(ScenarioRegistrationError):
        _registration("T1078", "slug", name="")
    with pytest.raises(ScenarioRegistrationError):
        _registration("T1078", "slug", aliases=("",))


def test_registration_rejects_duplicate_aliases() -> None:
    with pytest.raises(ScenarioRegistrationError):
        _registration("T1078", "slug", aliases=("dup", "dup"))


def test_registration_rejects_alias_duplicating_technique_or_slug() -> None:
    with pytest.raises(ScenarioRegistrationError):
        _registration("T1078", "slug", aliases=("t1078",))
    with pytest.raises(ScenarioRegistrationError):
        _registration("T1078", "myslug", aliases=("MYSLUG",))


def test_missing_capability_raises_typed_error() -> None:
    reg = _registration("T1078", "t1078")

    assert not has_capability(reg, ScenarioCapability.DETECTION)
    with pytest.raises(CapabilityMissingError) as excinfo:
        required_capability(reg, ScenarioCapability.DETECTION)
    assert "detection" in str(excinfo.value)


def test_required_capability_returns_callable_when_present() -> None:
    def simulate():
        return object()

    reg = _registration(
        "T1078",
        "t1078",
        caps=ScenarioCapabilities(simulation=simulate),
    )

    assert has_capability(reg, ScenarioCapability.SIMULATION)
    assert required_capability(reg, ScenarioCapability.SIMULATION) is simulate


def test_no_capability_invoked_during_registration_or_listing() -> None:
    calls: list[str] = []

    def simulate():
        calls.append("simulation")
        return None

    def detect():
        calls.append("detection")
        return None

    registry = ScenarioRegistry()
    registry.register(
        _registration(
            "T1078",
            "t1078",
            caps=ScenarioCapabilities(simulation=simulate, detection=detect),
        )
    )
    registry.resolve("T1078")
    registry.scenarios()

    assert calls == []


def test_metadata_loader_not_invoked_during_registry_use() -> None:
    registry = ScenarioRegistry()
    registry.register(_registration("T1078", "t1078"))  # loader is a sentinel

    registry.resolve("T1078")
    registry.scenarios()
