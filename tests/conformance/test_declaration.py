"""Declaration conformance for scenario authoring.

Proves that a scenario registration's capability callables are declared as
exact callables, resolve through ``has_capability``/``required_capability``,
and each run returns its documented result type. Both the built-in T1078
scenario and the independent probe must satisfy the same checks, which is
the point: the checks themselves never name a technique.
"""

from tests.conformance.builtin_pairs import SCENARIO_PAIRS
from tests.conformance.checks import (
    check_declared_capabilities,
    check_dependencies,
    check_metadata,
    check_registration_shape,
)
from tests.conformance.fixture import load_conformance_fixture

from duke.scenarios.registry import (
    ScenarioCapability,
    has_capability,
    required_capability,
)


def _fixtures():
    for name, registration, expectations in SCENARIO_PAIRS:
        yield name, load_conformance_fixture(registration, **expectations)


def test_metadata_conformance_holds_for_every_scenario():
    for name, fixture in _fixtures():
        for check in check_metadata(fixture):
            assert check.passed, f"[{name}] {check.name}: {check.detail}"
        for check in check_registration_shape(fixture):
            assert check.passed, f"[{name}] {check.name}: {check.detail}"


def test_declared_capabilities_hold_for_every_scenario():
    for name, fixture in _fixtures():
        for check in check_declared_capabilities(fixture):
            assert check.passed, f"[{name}] {check.name}: {check.detail}"


def test_lifecycle_dependencies_satisfied_for_every_scenario():
    for name, fixture in _fixtures():
        results = check_dependencies(fixture)
        assert results, f"[{name}] expected at least one dependency check"
        assert results[0].passed, f"[{name}] {results[0].name}: {results[0].detail}"


def test_every_scenario_provides_full_capability_set():
    """Both the production scenario and the probe declare the full vertical
    lifecycle: every capability is present and resolvable."""
    for name, fixture in _fixtures():
        registration = fixture.registration
        for capability in ScenarioCapability:
            assert has_capability(registration, capability), (
                f"[{name}] missing capability {capability.value}"
            )
            required_capability(registration, capability)  # must not raise
