"""Isolated registry conformance.

Exercises the reusable registry checks against an isolated
:class:`ScenarioRegistry` populated with both T1078 and the independent
probe. Resolution by canonical/slug/alias, deterministic ordering, and
duplicate rejection are all verified generically; nothing here assumes a
single scenario exists.
"""

import pytest
from tests.conformance.checks import check_registry_conformance
from tests.conformance.fixture import load_conformance_fixture
from tests.conformance.probe import probe_registration

from duke.scenarios.registry import (
    DuplicateScenarioError,
    ScenarioRegistry,
    UnknownScenarioError,
)

from .builtin_pairs import SCENARIO_PAIRS


@pytest.fixture(scope="module")
def isolated_registry() -> tuple[ScenarioRegistry, list]:
    """A fresh registry with both scenarios registered, plus their fixtures."""
    registry = ScenarioRegistry()
    fixtures = []
    for name, registration, expectations in SCENARIO_PAIRS:
        registry.register(registration)
        fixtures.append((name, load_conformance_fixture(registration, **expectations)))
    return registry, fixtures


def test_registry_conformance_for_every_scenario(isolated_registry):
    registry, fixtures = isolated_registry
    for name, fixture in fixtures:
        for check in check_registry_conformance(fixture, registry):
            assert check.passed, f"[{name}] {check.name}: {check.detail}"


def test_resolution_is_case_insensitive_and_disjoint(isolated_registry):
    """Resolution keys for the two scenarios never collide."""
    registry, fixtures = isolated_registry
    first = registry.resolve("T1078")
    second = registry.resolve("probe-observation")
    assert first is not second
    assert registry.resolve("T9999") is second
    assert registry.resolve("t1078_valid_accounts") is first


def test_registry_without_duplicates(isolated_registry):
    """The full-lifecycle conformance fixture registry holds T1078, T1110, and
    the independent probe (this is a test fixture, not the production built-in
    registry)."""
    registry, _ = isolated_registry
    assert len(registry.scenarios()) == 3


def test_production_builtin_registry_holds_only_the_three_builtins():
    """The production built-in registry holds exactly T1078, T1110, and the
    simulation-only T1566, and must never contain the probe; its count is
    distinct from the conformance fixture registry count above."""
    from duke.scenarios.builtins import builtin_registry

    registry = builtin_registry()
    ids = [registration.technique_id for registration in registry.scenarios()]
    assert ids == ["T1078", "T1110", "T1566"]
    assert "T9999" not in ids


def test_unknown_scenario_raises(isolated_registry):
    registry, _ = isolated_registry
    with pytest.raises(UnknownScenarioError):
        registry.resolve("totally-unknown-slug")


def test_colliding_registration_rejected():
    """Two registrations sharing a key must be rejected on registration."""
    probe = probe_registration()
    registry = ScenarioRegistry()
    registry.register(probe)
    with pytest.raises(DuplicateScenarioError):
        registry.register(probe)
