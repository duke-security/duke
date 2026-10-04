"""Composition root: wires the built-in scenarios into the registry.

This module is the single place that imports capability callables from the
T1078 implementation packages and registers them. It is the **only** module
in ``duke.scenarios`` that depends on the capability packages, and it is
deliberately **not** imported by ``duke.scenarios.__init__``.

Why: capability modules (notably ``duke.simulation.t1078``) import from
``duke.scenarios`` (for the packaged metadata loader). If
``duke.scenarios/__init__`` eagerly imported this composition root, we would
create a circular import. Importing it only from the CLI (and tests) keeps
the ``duke.scenarios -> capabilities -> duke.scenarios`` chain safe.

This module registers callable references only. Nothing is invoked during
registration or import; each capability runs only when the CLI calls it.
"""

from duke.core import Scenario
from duke.detection import detect_t1078, detect_t1110
from duke.investigation import investigate_t1078, investigate_t1110
from duke.learning import t1078_learning_path, t1110_learning_path
from duke.reporting import report_t1078, report_t1110
from duke.response import plan_t1078_response, plan_t1110_response
from duke.scenarios.loader import load_builtin_scenario
from duke.scenarios.registry import (
    ScenarioCapabilities,
    ScenarioRegistration,
    ScenarioRegistry,
)
from duke.simulation import (
    generate_t1078_simulation,
    generate_t1110_simulation,
    generate_t1566_simulation,
)
from duke.validation import validate_t1078, validate_t1110

_T1078_SLUG = "t1078_valid_accounts"
_T1110_SLUG = "t1110_brute_force"
_T1566_SLUG = "t1566_phishing"


def load_t1078_metadata() -> Scenario:
    """Load the packaged T1078 scenario metadata from its YAML definition."""
    return load_builtin_scenario(_T1078_SLUG)


def load_t1110_metadata() -> Scenario:
    """Load the packaged T1110 scenario metadata from its YAML definition."""
    return load_builtin_scenario(_T1110_SLUG)


def load_t1566_metadata() -> Scenario:
    """Load the packaged T1566 scenario metadata from its YAML definition."""
    return load_builtin_scenario(_T1566_SLUG)


def t1078_registration() -> ScenarioRegistration:
    """Build the deterministic T1078 registration."""
    return ScenarioRegistration(
        technique_id="T1078",
        slug=_T1078_SLUG,
        name="Valid Accounts: Compromised Identity",
        aliases=("valid-accounts",),
        metadata_loader=load_t1078_metadata,
        capabilities=ScenarioCapabilities(
            simulation=generate_t1078_simulation,
            detection=detect_t1078,
            investigation=investigate_t1078,
            response=plan_t1078_response,
            validation=validate_t1078,
            reporting=report_t1078,
            learning=t1078_learning_path,
        ),
    )


def t1110_registration() -> ScenarioRegistration:
    """Build the deterministic T1110 registration.

    T1110 now provides all seven registered lifecycle capabilities:
    simulation, detection, investigation, response, validation, reporting,
    and learning. The behaviour models sub-technique T1110.003 (Password
    Spraying), which is surfaced as a friendly alias alongside the canonical
    technique ID (T1110) and slug.
    """
    return ScenarioRegistration(
        technique_id="T1110",
        slug=_T1110_SLUG,
        name="Brute Force: Password Spraying",
        aliases=("brute-force", "T1110.003"),
        metadata_loader=load_t1110_metadata,
        capabilities=ScenarioCapabilities(
            simulation=generate_t1110_simulation,
            detection=detect_t1110,
            investigation=investigate_t1110,
            response=plan_t1110_response,
            validation=validate_t1110,
            reporting=report_t1110,
            learning=t1110_learning_path,
        ),
    )


def t1566_registration() -> ScenarioRegistration:
    """Build the deterministic T1566 registration.

    T1566 is registered as a **simulation-only** slice. The canonical
    technique ID is ``T1566`` (Phishing), matching the pattern set by T1078
    and T1110; the specific behaviour model is the sub-technique, surfaced as
    a friendly alias (``T1566.002``) alongside the slug. Only the simulation
    capability is provided; detection, investigation, response, validation,
    reporting, and learning are intentionally not yet implemented and remain
    ``None`` so unsupported lifecycle commands fail safely through the
    registry's missing-capability path.
    """
    return ScenarioRegistration(
        technique_id="T1566",
        slug=_T1566_SLUG,
        name="Phishing: Spearphishing Link",
        aliases=("phishing", "T1566.002"),
        metadata_loader=load_t1566_metadata,
        capabilities=ScenarioCapabilities(
            simulation=generate_t1566_simulation,
        ),
    )


def builtin_registry() -> ScenarioRegistry:
    """Return a fresh registry with all built-in scenarios registered.

    A new instance is built each call so there is no hidden shared mutable
    state and no import-time execution. Rebuilding deterministically
    re-runs the duplicate-protection checks.
    """
    registry = ScenarioRegistry()
    registry.register(t1078_registration())
    registry.register(t1110_registration())
    registry.register(t1566_registration())
    return registry


__all__ = [
    "builtin_registry",
    "load_t1078_metadata",
    "load_t1110_metadata",
    "load_t1566_metadata",
    "t1078_registration",
    "t1110_registration",
    "t1566_registration",
]
