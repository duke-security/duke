"""Production built-in / CLI conformance.

Confirms the shipped registry contains exactly the one built-in scenario
(T1078), that CLI resolution and the packaged metadata agree with its
registration, and — via an AST-based guard — that the reusable conformance
infrastructure remains independent of the T1078 implementation modules.

The generic metadata agreement checks deliberately do **not** require YAML;
the T1078-specific YAML agreement is asserted only here, in the production
conformance test.
"""

import ast
from pathlib import Path

from tests.conformance.builtin_pairs import SCENARIO_PAIRS
from tests.conformance.checks import check_metadata, check_registration_shape
from tests.conformance.fixture import load_conformance_fixture

from duke.scenarios.builtins import builtin_registry

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


def test_builtin_registry_contains_only_t1078():
    registry = builtin_registry()
    registrations = registry.scenarios()
    assert [reg.technique_id for reg in registrations] == ["T1078"]


def test_cli_resolves_the_builtin_scenario():
    registry = builtin_registry()
    assert registry.resolve("T1078").technique_id == "T1078"
    assert registry.resolve("t1078_valid_accounts").technique_id == "T1078"
    assert registry.resolve("valid-accounts").technique_id == "T1078"


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
