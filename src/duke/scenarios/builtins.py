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
from duke.detection import detect_t1078
from duke.investigation import investigate_t1078
from duke.learning import t1078_learning_path
from duke.reporting import report_t1078
from duke.response import plan_t1078_response
from duke.scenarios.loader import load_builtin_scenario
from duke.scenarios.registry import (
    ScenarioCapabilities,
    ScenarioRegistration,
    ScenarioRegistry,
)
from duke.simulation import generate_t1078_simulation
from duke.validation import validate_t1078

_T1078_SLUG = "t1078_valid_accounts"


def load_t1078_metadata() -> Scenario:
    """Load the packaged T1078 scenario metadata from its YAML definition."""
    return load_builtin_scenario(_T1078_SLUG)


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


def builtin_registry() -> ScenarioRegistry:
    """Return a fresh registry with all built-in scenarios registered.

    A new instance is built each call so there is no hidden shared mutable
    state and no import-time execution. Rebuilding deterministically
    re-runs the duplicate-protection checks.
    """
    registry = ScenarioRegistry()
    registry.register(t1078_registration())
    return registry


__all__ = [
    "builtin_registry",
    "load_t1078_metadata",
    "t1078_registration",
]
