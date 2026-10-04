"""Production built-in / CLI conformance.

Confirms the shipped registry contains the three static built-in scenarios
(T1078 and T1110, both full-lifecycle, plus the simulation-only T1566), that
CLI resolution and the packaged metadata agree with their registrations, and
— via an AST-based guard — that the reusable conformance infrastructure
remains independent of the T1078 implementation modules.

The generic metadata agreement checks deliberately do **not** require YAML;
the scenario-specific YAML agreement is asserted only here, in the production
conformance test.
"""

import ast
from pathlib import Path

from tests.conformance.builtin_pairs import SCENARIO_PAIRS
from tests.conformance.checks import (
    check_artefact,
    check_dependencies,
    check_detection,
    check_learning,
    check_metadata,
    check_registration_shape,
    check_registry_conformance,
    check_relationships,
    check_reporting,
    check_safe_response,
    check_simulation,
    check_validation,
)
from tests.conformance.fixture import load_conformance_fixture

from duke.scenarios.builtins import (
    builtin_registry,
    t1110_registration,
    t1566_registration,
)

# Modules that must remain implementation-independent so the conformance
# infrastructure can be reused for future scenarios without coupling.
_INDEPENDENT_SOURCES = ("fixture.py", "checks.py", "probe.py")
_FORBIDDEN_IMPORTS = (
    "duke.simulation.t1078",
    "duke.detection.t1078",
    "duke.investigation.t1078",
    "duke.response.t1078",
    "duke.validation.t1078",
    "duke.reporting.t1078",
    "duke.learning.t1078",
)


def _imported_module_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_builtin_registry_contains_the_three_static_scenarios():
    registry = builtin_registry()
    registrations = registry.scenarios()
    assert [reg.technique_id for reg in registrations] == [
        "T1078",
        "T1110",
        "T1566",
    ]


def test_cli_resolves_the_builtin_scenario():
    registry = builtin_registry()
    assert registry.resolve("T1078").technique_id == "T1078"
    assert registry.resolve("t1078_valid_accounts").technique_id == "T1078"
    assert registry.resolve("valid-accounts").technique_id == "T1078"


def test_cli_resolves_the_t1566_scenario():
    """Canonical T1566, its slug, and both aliases resolve; the canonical ID
    stays T1566 while the behaviour is surfaced via the T1566.002 alias."""
    registry = builtin_registry()
    assert registry.resolve("T1566").technique_id == "T1566"
    assert registry.resolve("t1566_phishing").technique_id == "T1566"
    assert registry.resolve("phishing").technique_id == "T1566"
    assert registry.resolve("T1566.002").technique_id == "T1566"


def test_t1566_is_simulation_only():
    """T1566 exposes simulation only; every other lifecycle capability is
    absent (None), so unsupported commands fail safely."""
    from duke.scenarios.registry import (
        ScenarioCapability,
        has_capability,
        required_capability,
    )

    reg = t1566_registration()
    for capability in ScenarioCapability:
        if capability is ScenarioCapability.SIMULATION:
            assert has_capability(reg, capability)
            assert required_capability(reg, capability) is not None
        else:
            assert not has_capability(reg, capability)


def test_t1110_metadata_agrees_via_generic_checks():
    """The partial built-in (simulation + detection + investigation +
    response + validation + reporting) passes the same generic metadata and
    registration-shape checks as T1078 and the probe. It is deliberately not
    part of the full-lifecycle SCENARIO_PAIRS; only the generic checks apply
    to this partial scenario."""
    reg = t1110_registration()
    fixture = load_conformance_fixture(
        reg,
        expected_entity_count=10,
        expected_event_count=8,
        expected_finding_count=1,
        expected_finding_technique="T1110",
    )
    for check in check_metadata(fixture):
        assert check.passed, f"[T1110.metadata] {check.name}: {check.detail}"
    for check in check_registration_shape(fixture):
        assert check.passed, f"[T1110.registration] {check.name}: {check.detail}"
    # Registry conformance requires the exact registration object to live in
    # the registry (identity-based resolution), so register ``reg`` into a
    # fresh isolated registry rather than reusing the fresh built-in registry,
    # which would hold a distinct equal registration object.
    from duke.scenarios.registry import ScenarioRegistry

    isolated = ScenarioRegistry()
    isolated.register(reg)
    for check in check_registry_conformance(fixture, isolated):
        assert check.passed, f"[T1110.registry] {check.name}: {check.detail}"


def test_t1110_simulation_conforms_generically():
    """The T1110 simulation, its canonical artefact, and its detection all
    satisfy the generic behavioural invariants (determinism, valid
    relationship references, non-empty artefact). Investigation is declared
    and its dependency on detection is satisfied. Response, validation,
    reporting, and learning are still absent, so those checks report passing
    skips."""
    reg = t1110_registration()
    fixture = load_conformance_fixture(
        reg,
        expected_entity_count=10,
        expected_event_count=8,
        expected_finding_count=1,
        expected_finding_technique="T1110",
    )
    for check in check_simulation(fixture):
        assert check.passed, f"[T1110.simulation] {check.name}: {check.detail}"
    for check in check_artefact(fixture):
        assert check.passed, f"[T1110.artefact] {check.name}: {check.detail}"
    for check in check_relationships(fixture):
        assert check.passed, f"[T1110.relationships] {check.name}: {check.detail}"
    # Detection is now provided and must be deterministic, produce exactly one
    # finding, and carry the T1110 technique.
    for check in check_detection(fixture):
        assert check.passed, f"[T1110.detection] {check.name}: {check.detail}"
    # Response / validation / reporting / learning remain unsupported and must
    # each report a passing skip.
    for check in check_safe_response(fixture):
        assert check.passed, f"[T1110.response] {check.name}: {check.detail}"
    for check in check_validation(fixture):
        assert check.passed, f"[T1110.validation] {check.name}: {check.detail}"
    for check in check_reporting(fixture):
        assert check.passed, f"[T1110.reporting] {check.name}: {check.detail}"
    for check in check_learning(fixture):
        assert check.passed, f"[T1110.learning] {check.name}: {check.detail}"
    assert check_dependencies(fixture)[0].passed, "[T1110.dependencies]"


def _t1566_conformance_fixture():
    """Build the canonical simulation-only T1566 conformance fixture.

    T1566 is deliberately **not** a member of ``SCENARIO_PAIRS`` (it is not
    full-lifecycle), so its generic metadata, registration-shape, registry,
    simulation, artefact, and relationship checks are exercised here as
    partial-production conformance, mirroring the established partial-scenario
    pattern."""
    reg = t1566_registration()
    fixture = load_conformance_fixture(
        reg,
        expected_entity_count=5,
        expected_event_count=6,
        expected_finding_count=0,
        expected_finding_technique="T1566",
    )
    return reg, fixture


def test_t1566_metadata_and_registration_agree_via_generic_checks():
    """The simulation-only T1566 scenario passes the same generic metadata and
    registration-shape checks as T1078, T1110, and the probe."""
    reg, fixture = _t1566_conformance_fixture()
    for check in check_metadata(fixture):
        assert check.passed, f"[T1566.metadata] {check.name}: {check.detail}"
    for check in check_registration_shape(fixture):
        assert check.passed, f"[T1566.registration] {check.name}: {check.detail}"
    from duke.scenarios.registry import ScenarioRegistry

    isolated = ScenarioRegistry()
    isolated.register(reg)
    for check in check_registry_conformance(fixture, isolated):
        assert check.passed, f"[T1566.registry] {check.name}: {check.detail}"


def test_t1566_simulation_conforms_generically():
    """The simulation-only T1566 simulation and its canonical artefact satisfy
    the generic behavioural invariants (determinism, stable ids, non-empty
    artefact, valid relationship references). Detection, response, validation,
    reporting, and learning are absent, so those checks report passing skips."""
    _, fixture = _t1566_conformance_fixture()
    for check in check_simulation(fixture):
        assert check.passed, f"[T1566.simulation] {check.name}: {check.detail}"
    for check in check_artefact(fixture):
        assert check.passed, f"[T1566.artefact] {check.name}: {check.detail}"
    for check in check_relationships(fixture):
        assert check.passed, f"[T1566.relationships] {check.name}: {check.detail}"
    # Unsupported capabilities must each report a passing skip, never fail.
    for check in check_detection(fixture):
        assert check.passed, f"[T1566.detection] {check.name}: {check.detail}"
    for check in check_safe_response(fixture):
        assert check.passed, f"[T1566.response] {check.name}: {check.detail}"
    for check in check_validation(fixture):
        assert check.passed, f"[T1566.validation] {check.name}: {check.detail}"
    for check in check_reporting(fixture):
        assert check.passed, f"[T1566.reporting] {check.name}: {check.detail}"
    for check in check_learning(fixture):
        assert check.passed, f"[T1566.learning] {check.name}: {check.detail}"



def test_t1078_metadata_agrees_via_generic_checks():
    """The production scenario passes the same generic metadata checks as
    the probe, validating the Scenario from its metadata_loader (no YAML
    required here)."""
    for name, registration, expectations in SCENARIO_PAIRS:
        if name != "T1078":
            continue
        fixture = load_conformance_fixture(registration, **expectations)
        for check in check_metadata(fixture):
            assert check.passed, f"[{name}] {check.name}: {check.detail}"
        for check in check_registration_shape(fixture):
            assert check.passed, f"[{name}] {check.name}: {check.detail}"


def test_conformance_sources_are_independent_of_t1078_implementations():
    """AST-parse the reusable conformance sources and reject any import from
    a T1078 implementation module. Uses the module tree, not substring
    matching, so a comment mentioning 't1078' cannot trip the guard."""
    conformance_dir = Path(__file__).resolve().parent
    forbidden = set(_FORBIDDEN_IMPORTS)
    for filename in _INDEPENDENT_SOURCES:
        imported = _imported_module_names(conformance_dir / filename)
        offending = sorted(forbidden & imported)
        assert not offending, f"{filename} imports implementation: {offending}"


def test_forbidden_import_list_matches_documented_modules():
    """The guard's forbidden list must correspond to the real T1078
    implementation package paths (via package directory naming)."""
    src = Path(__file__).resolve().parents[2] / "src"
    for forbidden in _FORBIDDEN_IMPORTS:
        module_file = src / f"{forbidden.replace('.', '/')}.py"
        assert module_file.exists(), (
            f"forbidden import targets a missing module: {forbidden} ({module_file})"
        )
