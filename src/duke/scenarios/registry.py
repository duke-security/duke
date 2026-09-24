"""Static built-in scenario registry and typed orchestration.

This module defines a **static, built-in** scenario registry: a fixed set
of scenarios (UTABLE) registered from code, not a dynamic plugin system.
It has no plugin or entry-point discovery, no third-party loading, and no
configuration database.

The registry's responsibility is to select the metadata and capability
callables for a scenario so that the CLI can resolve and dispatch without
hardcoding any particular technique. It holds callable references and
never invokes them during registration, listing, or resolution.

Import strategy: this module imports only ``duke.core`` and the *result*
types of the capability packages (none of which import ``duke.scenarios``),
so it cannot create a circular import. Capability callables themselves are
wired in ``duke.scenarios.builtins``, which is the single composition root
and deliberately not imported by ``duke.scenarios.__init__``.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, cast

from duke.core import Finding, Scenario
from duke.investigation.result import InvestigationResult
from duke.learning.models import LearningPath
from duke.reporting.result import IncidentReport
from duke.response.plan import ResponsePlan
from duke.simulation.result import SimulationResult
from duke.telemetry import TelemetryArtefact
from duke.validation.result import ValidationSuiteResult


class ScenarioCapability(StrEnum):
    """A lifecycle capability a scenario may provide.

    Member order is the canonical lifecycle order used for deterministic
    listing.
    """

    SIMULATION = "simulation"
    DETECTION = "detection"
    INVESTIGATION = "investigation"
    RESPONSE = "response"
    VALIDATION = "validation"
    REPORTING = "reporting"
    LEARNING = "learning"


# Exact callable type aliases matching the public capability signatures.
SimulationRun = Callable[..., SimulationResult]
DetectRun = Callable[..., tuple[Finding, ...]]
InvestigateRun = Callable[[TelemetryArtefact, Finding], InvestigationResult]
ResponsePlanRun = Callable[[TelemetryArtefact, InvestigationResult], ResponsePlan]
ValidationRun = Callable[[TelemetryArtefact], ValidationSuiteResult]
ReportRun = Callable[
    [
        TelemetryArtefact,
        Finding,
        InvestigationResult,
        ResponsePlan,
        ValidationSuiteResult,
    ],
    IncidentReport,
]
LearningRun = Callable[[], LearningPath]

CapabilityRun = Callable[..., Any]


@dataclass(frozen=True, slots=True)
class ScenarioCapabilities:
    """The lifecycle capabilities a scenario provides.

    Each field is optional: a scenario that does not implement a given
    capability simply leaves that field ``None``. Fields are typed to the
    exact public callable signatures above.
    """

    simulation: SimulationRun | None = None
    detection: DetectRun | None = None
    investigation: InvestigateRun | None = None
    response: ResponsePlanRun | None = None
    validation: ValidationRun | None = None
    reporting: ReportRun | None = None
    learning: LearningRun | None = None


class ScenarioRegistryError(ValueError):
    """Base for all scenario-registry errors."""


class ScenarioRegistrationError(ScenarioRegistryError):
    """Raised when a registration fails its own metadata validation."""


class DuplicateScenarioError(ScenarioRegistryError):
    """Raised when a registration collides with an already registered key."""


class UnknownScenarioError(ScenarioRegistryError):
    """Raised when a lookup key matches no registered scenario."""


class CapabilityMissingError(ScenarioRegistryError):
    """Raised when a scenario lacks a requested lifecycle capability."""


def _null_metadata_loader() -> Scenario:
    """Default metadata loader: used only when a registration omits one."""
    raise ScenarioRegistrationError("No metadata loader was provided")


def _normalize(value: str) -> str:
    """Fold a lookup value to its case-insensitive, stripped form."""
    return value.strip().lower()


@dataclass(frozen=True, slots=True)
class ScenarioRegistration:
    """A single registered scenario: metadata plus capability callables.

    The canonical ``technique_id`` and ``slug`` are preserved verbatim for
    display; lookup is case-insensitive. ``metadata_loader`` is a lazy,
    named callable (never a lambda) that yields the ``duke.core.Scenario``
    metadata on demand and is not invoked during registration.
    """

    technique_id: str
    slug: str
    name: str
    metadata_loader: Callable[[], Scenario]
    aliases: tuple[str, ...] = ()
    capabilities: ScenarioCapabilities = ScenarioCapabilities()

    def __post_init__(self) -> None:
        if not self.technique_id.strip():
            raise ScenarioRegistrationError("technique_id must not be empty")
        if not self.slug.strip():
            raise ScenarioRegistrationError("slug must not be empty")
        if not self.name.strip():
            raise ScenarioRegistrationError("name must not be empty")

        technique_key = _normalize(self.technique_id)

        seen: set[str] = set()
        for alias in self.aliases:
            if not alias.strip():
                raise ScenarioRegistrationError("aliases must not be empty")
            norm = _normalize(alias)
            if norm in seen:
                raise ScenarioRegistrationError(
                    f"Alias duplicates another alias: {alias!r}"
                )
            if norm == technique_key:
                raise ScenarioRegistrationError(
                    f"Alias {alias!r} duplicates the scenario's technique ID"
                )
            if norm == _normalize(self.slug):
                raise ScenarioRegistrationError(
                    f"Alias {alias!r} duplicates the scenario's slug"
                )
            seen.add(norm)

    def lookup_keys(self) -> tuple[str, ...]:
        """All case-insensitive keys that resolve to this registration."""
        keys = [_normalize(self.technique_id), _normalize(self.slug)]
        keys.extend(_normalize(alias) for alias in self.aliases)
        return tuple(dict.fromkeys(keys))


class ScenarioRegistry:
    """A typed collection of scenario registrations with deterministic lookup.

    Registration enforces duplicate protection over normalized keys
    (canonical ID, slug, and aliases). Resolution is case-insensitive and
    preserves each registration's canonical display values. The registry
    never executes a capability during registration, listing, or lookup.
    """

    def __init__(self) -> None:
        self._by_key: dict[str, ScenarioRegistration] = {}
        self._registrations: list[ScenarioRegistration] = []

    def register(self, registration: ScenarioRegistration) -> None:
        """Register a scenario, rejecting any normalized-key collision."""
        for key in registration.lookup_keys():
            existing = self._by_key.get(key)
            if existing is not None:
                raise DuplicateScenarioError(
                    f"Scenario {registration.technique_id!r} "
                    f"(slug {registration.slug!r}) collides on key {key!r}"
                    f" with scenario {existing.technique_id!r}"
                )
        for key in registration.lookup_keys():
            self._by_key[key] = registration
        self._registrations.append(registration)

    def resolve(self, key: str) -> ScenarioRegistration:
        """Resolve a scenario by technique ID, slug, or alias (case-insensitive)."""
        registration = self._by_key.get(_normalize(key))
        if registration is None:
            raise UnknownScenarioError(f"Unknown scenario: {key!r}")
        return registration

    def scenarios(self) -> tuple[ScenarioRegistration, ...]:
        """All registrations in deterministic order (technique ID, then slug)."""
        unique = {id(reg): reg for reg in self._registrations}
        ordered = sorted(
            unique.values(),
            key=lambda reg: (reg.technique_id.lower(), reg.slug),
        )
        return tuple(ordered)


def has_capability(
    registration: ScenarioRegistration,
    capability: ScenarioCapability,
) -> bool:
    """Return whether a scenario provides the given capability."""
    return getattr(registration.capabilities, capability.value, None) is not None


def required_capability(
    registration: ScenarioRegistration,
    capability: ScenarioCapability,
) -> CapabilityRun:
    """Return a scenario's capability callable, or raise if it is absent."""
    fn = getattr(registration.capabilities, capability.value, None)
    if fn is None:
        raise CapabilityMissingError(
            f"Scenario {registration.technique_id} ({registration.slug}) "
            f"does not provide capability {capability.value!r}"
        )
    return cast(CapabilityRun, fn)


__all__ = [
    "CapabilityMissingError",
    "CapabilityRun",
    "DetectRun",
    "DuplicateScenarioError",
    "InvestigateRun",
    "LearningRun",
    "ReportRun",
    "ResponsePlanRun",
    "ScenarioCapabilities",
    "ScenarioCapability",
    "ScenarioRegistration",
    "ScenarioRegistrationError",
    "ScenarioRegistry",
    "ScenarioRegistryError",
    "SimulationRun",
    "UnknownScenarioError",
    "ValidationRun",
    "has_capability",
    "required_capability",
]
