"""Reusable scenario-conformance check functions.

This module is test-only and scenario-independent. It must **never** import
from any ``duke.*.t1078`` implementation module; it operates only through the
``duke.scenarios`` registry, the shared result types, and a
:class:`ScenarioConformanceFixture`. This lets the same checks validate both
T1078 and the independent probe, and lets negative tests prove the checks
reject invalid scenarios.

Checks are pure: they return tuples of :class:`ConformanceCheck` describing a
named invariant, whether it held, and why. No check executes a real response
action or modifies anything.
"""

from dataclasses import dataclass

from tests.conformance.fixture import ScenarioConformanceFixture

from duke.core import ResponseStatus
from duke.learning import LearningPath
from duke.reporting import IncidentReport
from duke.response import ResponsePlan
from duke.scenarios.registry import (
    CapabilityMissingError,
    DuplicateScenarioError,
    ScenarioCapability,
    ScenarioRegistry,
    UnknownScenarioError,
    has_capability,
    required_capability,
)
from duke.simulation import SimulationResult
from duke.telemetry import TelemetryArtefact
from duke.validation import ValidationSuiteResult


@dataclass(frozen=True)
class ConformanceCheck:
    """A single named conformance invariant and its outcome."""

    name: str
    passed: bool
    detail: str

    def ok(self) -> bool:
        return self.passed


def _ok(name: str, passed: bool, detail: str = "") -> ConformanceCheck:
    return ConformanceCheck(name=name, passed=passed, detail=detail)


def _entity_ids(artefact: TelemetryArtefact) -> set[object]:
    return {entity.id for entity in artefact.entities}


def _event_ids(artefact: TelemetryArtefact) -> set[object]:
    return {event.id for event in artefact.events}


# ---- metadata / registration checks (constraint: generic, no YAML) ---------


def check_metadata(fixture: ScenarioConformanceFixture) -> tuple[ConformanceCheck, ...]:
    """Validate the ``Scenario`` returned by ``metadata_loader`` and its
    agreement with the registration where corresponding fields exist."""
    meta = fixture.metadata
    reg = fixture.registration
    return (
        _ok("metadata.name", bool(meta.name.strip()), meta.name),
        _ok("metadata.description", bool(meta.description.strip()), "non-empty"),
        _ok(
            "metadata.attack_technique_id",
            bool(meta.attack_technique_id.strip()),
            meta.attack_technique_id,
        ),
        _ok(
            "metadata.attack_tactics",
            len(meta.attack_tactics) >= 1,
            str(len(meta.attack_tactics)),
        ),
        _ok(
            "metadata.safety_notes",
            len(meta.safety_notes) >= 1,
            str(len(meta.safety_notes)),
        ),
        _ok("metadata.version", bool(meta.version.strip()), meta.version),
        _ok(
            "agreement.technique_id",
            reg.technique_id == meta.attack_technique_id,
            f"{reg.technique_id!r} vs {meta.attack_technique_id!r}",
        ),
        _ok("agreement.name", reg.name == meta.name, f"{reg.name!r} vs {meta.name!r}"),
    )


def check_registration_shape(
    fixture: ScenarioConformanceFixture,
) -> tuple[ConformanceCheck, ...]:
    """Validate the registration's slug and aliases independently of YAML."""
    reg = fixture.registration
    lower = {a.strip().lower() for a in reg.aliases}
    ok_aliases = all(a.strip() and len(lower) == len(reg.aliases) for a in reg.aliases)
    no_collision = (
        reg.slug.strip().lower() not in lower
        and reg.technique_id.strip().lower() not in lower
    )
    return (
        _ok("registration.slug", bool(reg.slug.strip()), reg.slug),
        _ok("registration.name", bool(reg.name.strip()), reg.name),
        _ok("registration.aliases_unique", ok_aliases, str(reg.aliases)),
        _ok("registration.aliases_no_collision", no_collision, str(reg.aliases)),
    )


# ---- declaration checks -----------------------------------------------------


def _is_simulation(value: object) -> bool:
    return isinstance(value, SimulationResult)


def check_declared_capabilities(
    fixture: ScenarioConformanceFixture,
) -> tuple[ConformanceCheck, ...]:
    """Verify that every declared capability resolves and yields its
    documented result type when invoked with its documented inputs."""
    reg = fixture.registration
    artefact = fixture.canonical_artefact
    checks: list[ConformanceCheck] = []

    sim = reg.capabilities.simulation
    checks.append(
        _ok(
            "declaration.simulation",
            _is_simulation(sim()) if sim is not None else False,
            "present",
        )
    )
    checks.append(
        _ok(
            "declaration.has_simulation",
            has_capability(reg, ScenarioCapability.SIMULATION),
            "",
        )
    )

    detect = reg.capabilities.detection
    if detect is not None:
        findings = detect(artefact.events)
        checks.append(
            _ok(
                "declaration.detection",
                isinstance(findings, tuple),
                f"{type(findings).__name__}",
            )
        )
    else:
        checks.append(_ok("declaration.detection", True, "not declared"))

    investigate = reg.capabilities.investigation
    if investigate is not None:
        checks.append(_ok("declaration.investigation", True, "declared"))
    else:
        checks.append(_ok("declaration.investigation", True, "not declared"))

    response = reg.capabilities.response
    checks.append(
        _ok(
            "declaration.response_required_capability",
            True,
            "",
        )
    )
    if response is not None:
        try:
            required_capability(reg, ScenarioCapability.RESPONSE)
            checks.append(_ok("declaration.response_resolves", True, ""))
        except CapabilityMissingError:
            checks.append(_ok("declaration.response_resolves", False, ""))

    validation = reg.capabilities.validation
    if validation is not None:
        checks.append(
            _ok(
                "declaration.validation",
                isinstance(validation(artefact), ValidationSuiteResult),
                "declared",
            )
        )
    else:
        checks.append(_ok("declaration.validation", True, "not declared"))

    reporting = reg.capabilities.reporting
    checks.append(_ok("declaration.reporting", True, ""))
    if reporting is not None:
        try:
            required_capability(reg, ScenarioCapability.REPORTING)
            checks.append(_ok("declaration.reporting_resolves", True, ""))
        except CapabilityMissingError:
            checks.append(_ok("declaration.reporting_resolves", False, ""))

    learning = reg.capabilities.learning
    if learning is not None:
        checks.append(
            _ok(
                "declaration.learning",
                isinstance(learning(), LearningPath),
                "declared",
            )
        )
    else:
        checks.append(_ok("declaration.learning", True, "not declared"))

    return tuple(checks)


def check_dependencies(
    fixture: ScenarioConformanceFixture,
) -> tuple[ConformanceCheck, ...]:
    """Verify that each provided capability's documented downstream inputs
    are satisfiable by the other provided capabilities (the lifecycle
    dependency rules). Detection and validation are each independent;
    investigation needs a Finding, response needs an InvestigationResult,
    and reporting needs finding + investigation + response + validation."""
    reg = fixture.registration
    detection = reg.capabilities.detection is not None
    investigation = reg.capabilities.investigation is not None
    response = reg.capabilities.response is not None
    validation = reg.capabilities.validation is not None
    reporting = reg.capabilities.reporting is not None

    if investigation and not detection:
        return (
            _ok(
                "dependency.investigation.needs_detection",
                False,
                "investigation provided but no detection to produce a Finding",
            ),
        )
    if response and not investigation:
        return (
            _ok(
                "dependency.response.needs_investigation",
                False,
                "response provided but no investigation to produce an Investigation"
                "Result",
            ),
        )
    if reporting and not (detection and investigation and response and validation):
        return (
            _ok(
                "dependency.reporting.needs_inputs",
                False,
                "reporting provided but detection/investigation/response/validation "
                "missing",
            ),
        )
    return (_ok("dependency.satisfied", True, "all provided inputs satisfiable"),)


# ---- registry checks --------------------------------------------------------


def check_registry_conformance(
    fixture: ScenarioConformanceFixture,
    registry: ScenarioRegistry,
) -> tuple[ConformanceCheck, ...]:
    """Verify resolution by any canonical key, deterministic listing, and
    duplicate protection over an isolated registry."""
    reg = fixture.registration
    keys = (reg.technique_id, reg.slug, *reg.aliases)
    resolve_checks: list[ConformanceCheck] = []
    for key in keys:
        try:
            resolved = registry.resolve(key)
            resolve_checks.append(_ok(f"registry.resolve.{key}", resolved is reg, ""))
        except UnknownScenarioError:
            resolve_checks.append(_ok(f"registry.resolve.{key}", False, "unknown"))
    resolve_checks.append(
        _ok(
            "registry.resolve.case_insensitive",
            registry.resolve(reg.technique_id.lower()) is reg,
            reg.technique_id,
        )
    )

    listed = registry.scenarios()
    sorted_ok = tuple(sorted(listed, key=lambda r: (r.technique_id.lower(), r.slug)))
    listing_checks = (
        _ok("registry.listing.deterministic", listed == sorted_ok, ""),
        _ok("registry.listing.contains", reg in listed, reg.technique_id),
    )

    try:
        registry.register(reg)
        duplicate_ok = _ok("registry.duplicate_rejected", False, "duplicate registered")
    except DuplicateScenarioError:
        duplicate_ok = _ok("registry.duplicate_rejected", True, "rejected duplicate")

    return (*resolve_checks, *listing_checks, duplicate_ok)


# ---- behavioural checks -----------------------------------------------------


def _result_equal(first: object, second: object) -> bool:
    return first == second


def check_simulation(
    fixture: ScenarioConformanceFixture,
) -> tuple[ConformanceCheck, ...]:
    """Run simulation twice and require identical, timezone-aware output."""
    simulation = fixture.registration.capabilities.simulation
    if simulation is None:
        return (_ok("simulation.skipped", True, "no simulation capability"),)
    first = simulation()
    second = simulation()
    same = _result_equal(first, second)
    aware = all(event.occurred_at.tzinfo is not None for event in first.events)
    stable_entity_ids = [e.id for e in first.entities] == [
        e.id for e in second.entities
    ]
    stable_event_ids = [e.id for e in first.events] == [e.id for e in second.events]
    return (
        _ok("simulation.deterministic", same, ""),
        _ok("simulation.timezone_aware", aware, ""),
        _ok("simulation.stable_entity_ids", stable_entity_ids, ""),
        _ok("simulation.stable_event_ids", stable_event_ids, ""),
    )


def check_artefact(fixture: ScenarioConformanceFixture) -> tuple[ConformanceCheck, ...]:
    """Validate the canonical artefact shape: non-empty, expected counts,
    and unique entity/event identifiers."""
    artefact = fixture.canonical_artefact
    entity_ids = _entity_ids(artefact)
    event_ids = _event_ids(artefact)
    return (
        _ok(
            "artefact.has_entities",
            len(artefact.entities) >= 1,
            str(len(artefact.entities)),
        ),
        _ok(
            "artefact.has_events",
            len(artefact.events) >= 1,
            str(len(artefact.events)),
        ),
        _ok(
            "artefact.unique_entity_ids",
            len(entity_ids) == len(artefact.entities),
            str(len(artefact.entities)),
        ),
        _ok(
            "artefact.unique_event_ids",
            len(event_ids) == len(artefact.events),
            str(len(artefact.events)),
        ),
    )


def check_relationships(
    fixture: ScenarioConformanceFixture,
) -> tuple[ConformanceCheck, ...]:
    """Require every event actor/target reference and every finding
    event/entity reference to resolve within the artefact."""
    artefact = fixture.canonical_artefact
    entity_ids = _entity_ids(artefact)
    event_ids = _event_ids(artefact)

    violated: list[str] = []
    for event in artefact.events:
        actor = event.actor_entity_id
        if actor is not None and actor not in entity_ids:
            violated.append(f"event {event.id} actor missing")
        for target in event.target_entity_ids:
            if target not in entity_ids:
                violated.append(f"event {event.id} target missing")

    detect = fixture.registration.capabilities.detection
    finding_violations: list[str] = []
    if detect is not None:
        for finding in detect(artefact.events):
            for eid in finding.event_ids:
                if eid not in event_ids:
                    finding_violations.append(f"finding {finding.id} event missing")
            for ent in finding.entity_ids:
                if ent not in entity_ids:
                    finding_violations.append(f"finding {finding.id} entity missing")

    return (
        _ok(
            "relationship.event_references",
            not violated,
            "; ".join(violated) if violated else "all events resolve",
        ),
        _ok(
            "relationship.finding_references",
            not finding_violations,
            "; ".join(finding_violations)
            if finding_violations
            else "all findings resolve",
        ),
    )



def check_detection(
    fixture: ScenarioConformanceFixture,
) -> tuple[ConformanceCheck, ...]:
    """Require deterministic detection with the expected finding count and
    technique."""
    detect = fixture.registration.capabilities.detection
    if detect is None:
        return (_ok("detection.skipped", True, "no detection capability"),)
    events = fixture.canonical_artefact.events
    first = detect(events)
    second = detect(events)
    deterministic = _result_equal(first, second)
    count_ok = len(first) == fixture.expected_finding_count
    technique_ok = all(
        f.technique_id == fixture.expected_finding_technique for f in first
    )
    return (
        _ok("detection.deterministic", deterministic, ""),
        _ok("detection.expected_count", count_ok, str(len(first))),
        _ok("detection.technique", technique_ok, fixture.expected_finding_technique),
    )


def _derive_plan(
    fixture: ScenarioConformanceFixture,
) -> ResponsePlan | None:
    """Derive a response plan from the declared detection → investigation →
    response callables, or ``None`` if any prerequisite is absent or yields
    nothing."""
    detect = fixture.registration.capabilities.detection
    investigate = fixture.registration.capabilities.investigation
    response = fixture.registration.capabilities.response
    if detect is None or investigate is None or response is None:
        return None
    findings = detect(fixture.canonical_artefact.events)
    if not findings:
        return None
    result = investigate(fixture.canonical_artefact, findings[0])
    return response(fixture.canonical_artefact, result)


def check_safe_response(
    fixture: ScenarioConformanceFixture,
) -> tuple[ConformanceCheck, ...]:
    """Require that every proposed response action is dry-run, approval-
    required, and PLANNED, and that the plan is deterministic."""
    response = fixture.registration.capabilities.response
    if response is None:
        return (_ok("response.skipped", True, "no response capability"),)
    plan = _derive_plan(fixture)
    if plan is None:
        return (_ok("response.prerequisites_unsatisfied", False, "no finding/result"),)
    detect = fixture.registration.capabilities.detection
    result = None
    if detect is not None:
        findings = detect(fixture.canonical_artefact.events)
        if findings and fixture.registration.capabilities.investigation is not None:
            result = fixture.registration.capabilities.investigation(
                fixture.canonical_artefact, findings[0]
            )
    if result is None:
        return (_ok("response.prerequisites_unsatisfied", False, "no finding/result"),)
    actions = plan.actions()
    dry = all(a.dry_run for a in actions)
    approval = all(a.requires_approval for a in actions)
    planned = all(a.status is ResponseStatus.PLANNED for a in actions)
    correl = plan.incident.finding_ids == [plan.finding.id]
    determinism_ok = plan == response(fixture.canonical_artefact, result)
    return (
        _ok("response.actions_dry_run", dry, ""),
        _ok("response.actions_require_approval", approval, ""),
        _ok("response.actions_planned", planned, ""),
        _ok("response.incident_correlates_finding", correl, ""),
        _ok("response.deterministic", determinism_ok, ""),
    )


def check_validation(
    fixture: ScenarioConformanceFixture,
) -> tuple[ConformanceCheck, ...]:
    """Require deterministic, passing validation where provided."""
    validation = fixture.registration.capabilities.validation
    if validation is None:
        return (_ok("validation.skipped", True, "no validation capability"),)
    first = validation(fixture.canonical_artefact)
    second = validation(fixture.canonical_artefact)
    deterministic = _result_equal(first, second)
    all_passed_ok = first.all_passed
    return (
        _ok("validation.deterministic", deterministic, ""),
        _ok("validation.all_passed", all_passed_ok, str(first.all_passed)),
    )


def check_reporting(
    fixture: ScenarioConformanceFixture,
) -> tuple[ConformanceCheck, ...]:
    """Require deterministic reporting where the full inputs are provided.

    This invokes reporting with its documented inputs. It does **not** verify
    Markdown or export bytes, which belong to the existing component tests."""
    reporting = fixture.registration.capabilities.reporting
    if reporting is None:
        return (_ok("reporting.skipped", True, "no reporting capability"),)
    detect = fixture.registration.capabilities.detection
    investigate = fixture.registration.capabilities.investigation
    response = fixture.registration.capabilities.response
    validation = fixture.registration.capabilities.validation
    if not (detect and investigate and response and validation):
        return (
            _ok(
                "reporting.inputs_unsatisfied",
                False,
                "reporting provided but missing inputs",
            ),
        )
    artefact = fixture.canonical_artefact
    findings = detect(artefact.events)
    if not findings:
        return (_ok("reporting.inputs_finding_missing", False, "no finding"),)
    finding = findings[0]
    result = investigate(artefact, finding)
    plan = response(artefact, result)
    suite = validation(artefact)
    first = reporting(artefact, finding, result, plan, suite)
    second = reporting(artefact, finding, result, plan, suite)
    return (
        _ok("reporting.deterministic", _result_equal(first, second), ""),
        _ok("reporting.content", isinstance(first, IncidentReport), ""),
    )


def check_learning(fixture: ScenarioConformanceFixture) -> tuple[ConformanceCheck, ...]:
    """Require a deterministic learning path where provided."""
    learning = fixture.registration.capabilities.learning
    if learning is None:
        return (_ok("learning.skipped", True, "no learning capability"),)
    first = learning()
    second = learning()
    deterministic = _result_equal(first, second)
    ordered = tuple(first.ordered_steps)
    ordered_ok = tuple(first.steps) == ordered
    return (
        _ok("learning.deterministic", deterministic, ""),
        _ok("learning.ordered", ordered_ok, ""),
    )
