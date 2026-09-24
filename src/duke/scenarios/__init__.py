"""Packaged scenarios, scenario loading, and the static scenario registry.

This package deliberately does **not** import ``duke.scenarios.builtins``:
that composition root wires the concrete capability callables and must be
imported from the CLI (or tests) only, to avoid a circular import through
the capability packages.
"""

from duke.scenarios.loader import ScenarioLoadError, load_builtin_scenario
from duke.scenarios.registry import (
    CapabilityMissingError,
    DuplicateScenarioError,
    ScenarioCapabilities,
    ScenarioCapability,
    ScenarioRegistration,
    ScenarioRegistrationError,
    ScenarioRegistry,
    ScenarioRegistryError,
    UnknownScenarioError,
    has_capability,
    required_capability,
)

__all__ = [
    "CapabilityMissingError",
    "DuplicateScenarioError",
    "ScenarioCapabilities",
    "ScenarioCapability",
    "ScenarioLoadError",
    "ScenarioRegistration",
    "ScenarioRegistrationError",
    "ScenarioRegistry",
    "ScenarioRegistryError",
    "UnknownScenarioError",
    "has_capability",
    "load_builtin_scenario",
    "required_capability",
]
