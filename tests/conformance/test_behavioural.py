"""Behavioural conformance: positive checks for every scenario and negative
checks proving each invariant is actually enforced.

Positive tests run the reusable behavioural checks over both T1078 and the
independent probe. Negative tests build deliberately broken scenarios and
assert that the specific invariant violated is reported as failing — so a
future scenario that breaks a rule fails here for the right reason.
"""

import dataclasses
from datetime import UTC, datetime
from uuid import uuid4

from tests.conformance.builtin_pairs import SCENARIO_PAIRS
from tests.conformance.checks import (
    check_artefact,
    check_dependencies,
    check_detection,
    check_learning,
    check_relationships,
    check_reporting,
    check_safe_response,
    check_simulation,
    check_validation,
)
from tests.conformance.fixture import (
    ScenarioConformanceFixture,
    load_conformance_fixture,
)
from tests.conformance.probe import probe_registration

from duke.core import (
    Entity,
    EntityType,
    EventOutcome,
    Finding,
    FindingStatus,
    ResponseStatus,
    SecurityEvent,
    Severity,
)
from duke.response import ResponseActionGroup
from duke.scenarios.registry import ScenarioCapabilities, ScenarioRegistration
from duke.telemetry import TelemetryArtefact


def _now() -> datetime:
    return datetime.now(UTC)


def _entity(identifier: str, *, entity_id=None) -> Entity:
    return Entity(
        entity_type=EntityType.USER,
        identifier=identifier,
        display_name=identifier,
        **({"id": entity_id} if entity_id is not None else {}),
    )


def _event(*, event_id=None, actor=None, targets=(), occurred_at=None) -> SecurityEvent:
    return SecurityEvent(
        occurred_at=occurred_at if occurred_at is not None else _now(),
        action="authenticate",
        outcome=EventOutcome.SUCCESS,
        source="identity_provider",
        actor_entity_id=actor,
        target_entity_ids=list(targets),
        **({"id": event_id} if event_id is not None else {}),
    )


def _fixture(registration: ScenarioRegistration, artefact: TelemetryArtefact):
    return ScenarioConformanceFixture(
        registration=registration,
        metadata=registration.metadata_loader(),
        canonical_artefact=artefact,
        expected_entity_count=len(artefact.entities),
        expected_event_count=len(artefact.events),
        expected_finding_count=1,
        expected_finding_technique=registration.technique_id,
    )


def _probe_capabilities(**overrides) -> ScenarioCapabilities:
    probe = probe_registration()
    return dataclasses.replace(probe.capabilities, **overrides)


def _probe_registration(capabilities: ScenarioCapabilities) -> ScenarioRegistration:
    probe = probe_registration()
    return dataclasses.replace(probe, capabilities=capabilities)


def _cap_fixture(capabilities: ScenarioCapabilities, artefact: TelemetryArtefact):
    """A conformance fixture bound to a (possibly overridden) capability set."""
    return _fixture(_probe_registration(capabilities), artefact)


def _passing_artefact() -> TelemetryArtefact:
    actor = _entity("actor")
    target = _entity("target")
    event = _event(actor=actor.id, targets=(target.id,))
    return TelemetryArtefact(entities=(actor, target), events=(event,))


def _probe_artefact() -> TelemetryArtefact:
    """The real probe simulation output, so detection/investigation resolve."""
    simulation = probe_registration().capabilities.simulation
    assert simulation is not None
    result = simulation()
    return TelemetryArtefact(entities=result.entities, events=result.events)


# ---- positive: both scenarios satisfy every behavioural invariant ----------


def test_behavioural_checks_pass_for_every_scenario():
    groups = (
        ("simulation", check_simulation),
        ("artefact", check_artefact),
        ("relationships", check_relationships),
        ("detection", check_detection),
        ("safe_response", check_safe_response),
        ("validation", check_validation),
        ("reporting", check_reporting),
        ("learning", check_learning),
    )
    for name, registration, expectations in SCENARIO_PAIRS:
        fixture = load_conformance_fixture(registration, **expectations)
        for group, check in groups:
            for result in check(fixture):
                assert result.passed, (
                    f"[{name}.{group}] {result.name}: {result.detail}"
                )


# ---- negative: each broken scenario fails for its intended invariant -------


def _assert_invariant_fails(*, group, invariant, checks):
    outcomes = [(c.name, c.passed) for c in checks]
    assert (
        any(c.name == invariant and not c.passed for c in checks)
    ), f"expected {invariant!r} (in {group}) to fail; got {outcomes}"


def test_duplicate_entity_ids_detected():
    shared = uuid4()
    artefact = TelemetryArtefact(
        entities=(_entity("a", entity_id=shared), _entity("b", entity_id=shared)),
        events=(_event(actor=shared),),
    )
    checks = check_artefact(_cap_fixture(_probe_capabilities(), artefact))
    _assert_invariant_fails(
        group="artefact",
        invariant="artefact.unique_entity_ids",
        checks=checks,
    )


def test_duplicate_event_ids_detected():
    shared = uuid4()
    actor = _entity("a")
    artefact = TelemetryArtefact(
        entities=(actor,),
        events=(
            _event(event_id=shared, actor=actor.id),
            _event(event_id=shared, actor=actor.id),
        ),
    )
    checks = check_artefact(_cap_fixture(_probe_capabilities(), artefact))
    _assert_invariant_fails(
        group="artefact",
        invariant="artefact.unique_event_ids",
        checks=checks,
    )


def test_event_referencing_missing_actor_entity_detected():
    artefact = TelemetryArtefact(
        entities=(_entity("a"),),
        events=(_event(actor=uuid4()),),
    )
    # detection disabled so only the event-reference invariant is exercised
    capabilities = _probe_capabilities(detection=None)
    checks = check_relationships(_cap_fixture(capabilities, artefact))
    _assert_invariant_fails(
        group="relationships",
        invariant="relationship.event_references",
        checks=checks,
    )


def test_event_referencing_missing_target_entity_detected():
    artefact = TelemetryArtefact(
        entities=(_entity("a"),),
        events=(_event(actor=None, targets=(uuid4(),)),),
    )
    capabilities = _probe_capabilities(detection=None)
    checks = check_relationships(_cap_fixture(capabilities, artefact))
    _assert_invariant_fails(
        group="relationships",
        invariant="relationship.event_references",
        checks=checks,
    )


def test_finding_referencing_missing_event_or_entity_detected():
    actor = _entity("a")
    good_event = _event(actor=actor.id)
    artefact = TelemetryArtefact(entities=(actor,), events=(good_event,))

    def bad_detect(events):
        return (
            Finding(
                created_at=_now(),
                title="bad",
                description="bad",
                detection_name="bad",
                detection_details="bad",
                severity=Severity.MEDIUM,
                status=FindingStatus.NEW,
                event_ids=[uuid4()],  # references an event that does not exist
                entity_ids=[uuid4()],  # references an entity that does not exist
                technique_id="T9999",
                confidence=80,
            ),
        )

    capabilities = _probe_capabilities(detection=bad_detect)
    checks = check_relationships(_cap_fixture(capabilities, artefact))
    _assert_invariant_fails(
        group="relationships",
        invariant="relationship.finding_references",
        checks=checks,
    )


def test_nondeterministic_simulation_detected():
    from duke.simulation.result import SimulationResult

    def flaky():
        event = _event(occurred_at=_now())
        return SimulationResult(
            scenario=probe_registration().metadata_loader(),
            entities=(_entity("a"),),
            events=(event,),
        )

    capabilities = _probe_capabilities(simulation=flaky)
    checks = check_simulation(_cap_fixture(capabilities, _passing_artefact()))
    _assert_invariant_fails(
        group="simulation",
        invariant="simulation.deterministic",
        checks=checks,
    )


def test_nondeterministic_detection_detected():
    def flaky_detect(events):
        return (
            Finding(
                created_at=_now(),
                title="flaky",
                description="flaky",
                detection_name="flaky",
                detection_details="flaky",
                severity=Severity.MEDIUM,
                status=FindingStatus.NEW,
                event_ids=[e.id for e in events],
                entity_ids=[],
                technique_id="T9999",
                confidence=80,
            ),
        )

    capabilities = _probe_capabilities(detection=flaky_detect)
    checks = check_detection(_cap_fixture(capabilities, _passing_artefact()))
    _assert_invariant_fails(
        group="detection",
        invariant="detection.deterministic",
        checks=checks,
    )


def _patched_response(**action_overrides):
    """Wrap the probe's response so one action carries the given overrides."""
    real = probe_registration().capabilities.response
    assert real is not None

    def response(artefact, result):
        plan = real(artefact, result)
        actions = list(plan.actions())
        actions[0] = actions[0].model_copy(update=action_overrides)
        rebuilt = []
        index = 0
        for group in plan.groups:
            group_actions = []
            for _ in group.actions:
                group_actions.append(actions[index])
                index += 1
            rebuilt.append(
                ResponseActionGroup(
                    category=group.category,
                    actions=tuple(group_actions),
                )
            )
        return plan.model_copy(update={"groups": tuple(rebuilt)})

    return response


def test_non_dry_run_response_action_detected():
    caps = _probe_capabilities(response=_patched_response(dry_run=False))
    checks = check_safe_response(_cap_fixture(caps, _probe_artefact()))
    _assert_invariant_fails(
        group="response",
        invariant="response.actions_dry_run",
        checks=checks,
    )


def test_response_action_not_requiring_approval_detected():
    caps = _probe_capabilities(response=_patched_response(requires_approval=False))
    checks = check_safe_response(_cap_fixture(caps, _probe_artefact()))
    _assert_invariant_fails(
        group="response",
        invariant="response.actions_require_approval",
        checks=checks,
    )


def test_response_action_status_not_planned_detected():
    caps = _probe_capabilities(
        response=_patched_response(status=ResponseStatus.COMPLETED)
    )
    checks = check_safe_response(_cap_fixture(caps, _probe_artefact()))
    _assert_invariant_fails(
        group="response",
        invariant="response.actions_planned",
        checks=checks,
    )


def test_investigation_without_detection_is_unsatisfied():
    caps = _probe_capabilities(detection=None)
    checks = check_dependencies(_cap_fixture(caps, _passing_artefact()))
    _assert_invariant_fails(
        group="dependencies",
        invariant="dependency.investigation.needs_detection",
        checks=checks,
    )


def test_response_without_investigation_is_unsatisfied():
    caps = _probe_capabilities(investigation=None, reporting=None)
    checks = check_dependencies(_cap_fixture(caps, _passing_artefact()))
    _assert_invariant_fails(
        group="dependencies",
        invariant="dependency.response.needs_investigation",
        checks=checks,
    )


def test_reporting_without_inputs_is_unsatisfied():
    caps = _probe_capabilities(validation=None)
    checks = check_dependencies(_cap_fixture(caps, _passing_artefact()))
    _assert_invariant_fails(
        group="dependencies",
        invariant="dependency.reporting.needs_inputs",
        checks=checks,
    )
