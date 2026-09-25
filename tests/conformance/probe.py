"""A test-only, independent probe scenario.

The probe is a deliberately small, fully in-memory scenario used to prove
that the reusable conformance infrastructure is not secretly coupled to
T1078. It implements the full lifecycle with generic, deterministic
callables and its own UUID namespace, and imports **no** ``duke.*.t1078``
module.

The probe is test-only:

- it lives entirely under ``tests/``;
- it has no packaged ``scenario.yaml`` (metadata is built in memory);
- it is never registered into ``duke.scenarios.builtins.builtin_registry()``;
- it is exercised only through an isolated :class:`ScenarioRegistry` built
  here.
"""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5

from duke.core import (
    Entity,
    EntityType,
    EventOutcome,
    Evidence,
    EvidenceRelationship,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    ResponseAction,
    ResponseRisk,
    ResponseStatus,
    Scenario,
    SecurityEvent,
    Severity,
)
from duke.investigation import InvestigationResult, TimelineEntry
from duke.learning import (
    Exercise,
    Hint,
    KnowledgeCheck,
    LearningObjective,
    LearningPath,
    LearningStep,
)
from duke.reporting import IncidentReport
from duke.response import (
    ResponseActionGroup,
    ResponseCategory,
    ResponsePlan,
)
from duke.scenarios.registry import (
    ScenarioCapabilities,
    ScenarioRegistration,
    ScenarioRegistry,
)
from duke.simulation.result import SimulationResult
from duke.telemetry import TelemetryArtefact
from duke.validation import (
    ValidationCase,
    ValidationStatus,
    ValidationSuiteResult,
)

_PROBE_NAMESPACE = UUID("99990000-0000-4000-8000-000000000000")
_TECHNIQUE = "T9999"


def _id(value: str) -> UUID:
    """Return a repeatable identifier for synthetic probe data."""
    return uuid5(_PROBE_NAMESPACE, value)


def probe_metadata_loader() -> Scenario:
    """Return the in-memory probe ``Scenario`` metadata (no YAML)."""
    return Scenario(
        id=_id("scenario"),
        name="Probe Observation",
        description=(
            "A minimal synthetic scenario proving the conformance "
            "infrastructure is independent of any specific ATT&CK technique."
        ),
        attack_technique_id=_TECHNIQUE,
        attack_tactics=["Initial Access"],
        learning_objectives=["Recognise a minimal behaviour sequence."],
        python_concepts=["Deterministic test data"],
        telemetry_requirements=["Authentication activity", "File read activity"],
        safety_notes=["Uses only synthetic entities and events."],
        version="0.0.1",
        last_reviewed=datetime(2026, 9, 24).date(),
    )


def _account() -> Entity:
    return Entity(
        id=_id("entity:account"),
        entity_type=EntityType.ACCOUNT,
        identifier="probe.user@example.lab",
        display_name="Probe User",
    )


def _device() -> Entity:
    return Entity(
        id=_id("entity:device"),
        entity_type=EntityType.HOST,
        identifier="probe-device",
        display_name="Probe Device",
    )


def _secret() -> Entity:
    return Entity(
        id=_id("entity:secret"),
        entity_type=EntityType.FILE,
        identifier="probe/secret.txt",
        display_name="Probe Secret",
    )


def _event(
    sequence: int,
    at: datetime,
    action: str,
    *,
    device: Entity,
    **attrs: str,
) -> SecurityEvent:
    """Build a deterministic probe security event."""
    return SecurityEvent(
        id=_id(f"event:{sequence}:{action}"),
        occurred_at=at,
        action=action,
        outcome=EventOutcome.SUCCESS,
        source="identity_provider",
        actor_entity_id=_account().id,
        target_entity_ids=[device.id],
        attributes=attrs,
    )


def generate_probe_simulation() -> SimulationResult:
    """Generate a small, deterministic probe behaviour sequence."""
    start = datetime(2026, 9, 24, 9, 0, tzinfo=UTC)
    entities = (_account(), _device(), _secret())
    events = (
        _event(
            1,
            start,
            "authenticate",
            device=_device(),
            network_context="known",
            device_context="known",
        ),
        _event(
            2,
            start + timedelta(hours=8),
            "authenticate",
            device=_device(),
            network_context="new",
            device_context="unfamiliar",
        ),
        _event(
            3,
            start + timedelta(hours=8, minutes=2),
            "read_file",
            device=_device(),
            data_classification="restricted",
        ),
    )
    return SimulationResult(
        scenario=probe_metadata_loader(),
        entities=entities,
        events=events,
    )


def detect_probe(events: Sequence[SecurityEvent]) -> tuple[Finding, ...]:
    """Return a deterministic single finding for the probe corpus."""
    actor = _account().id
    new_login = next(
        (
            e
            for e in events
            if e.action == "authenticate"
            and e.attributes.get("network_context") == "new"
            and e.actor_entity_id == actor
        ),
        None,
    )
    if new_login is None:
        return ()
    return (
        Finding(
            id=_id(f"finding:{actor}"),
            created_at=new_login.occurred_at,
            title="Probe new-context login",
            description="A new-context login followed by restricted access.",
            detection_name="probe-new-context-login",
            detection_details="New-context login plus restricted read.",
            technique_id=_TECHNIQUE,
            severity=Severity.HIGH,
            status=FindingStatus.NEW,
            event_ids=[e.id for e in events],
            entity_ids=[actor, _device().id, _secret().id],
            confidence=80,
        ),
    )


def investigate_probe(
    artefact: TelemetryArtefact,
    finding: Finding,
) -> InvestigationResult:
    """Build a minimal evidence-led investigation for the probe finding."""
    events_by_id = {event.id: event for event in artefact.events}
    referenced = [
        events_by_id[eid]
        for eid in finding.event_ids
        if eid in events_by_id
    ]
    ordered = sorted(referenced, key=lambda e: e.occurred_at)
    evidence = tuple(
        Evidence(
            id=_id(f"evidence:{event.id}"),
            collected_at=event.occurred_at,
            description=f"Probe event {event.action}.",
            relationship=EvidenceRelationship.SUPPORTS,
            source_event_id=event.id,
        )
        for event in ordered
    )
    timeline = tuple(
        TimelineEntry(
            occurred_at=event.occurred_at,
            event_id=event.id,
            summary=event.action,
            entity_ids=tuple(
                e
                for e in (event.actor_entity_id, *event.target_entity_ids)
                if e is not None
            ),
        )
        for event in ordered
    )
    involved = tuple(
        entity
        for entity in artefact.entities
        if entity.id in set(finding.entity_ids)
    )
    return InvestigationResult(
        finding=finding,
        involved_entities=involved,
        evidence=evidence,
        timeline=timeline,
        confirmed_facts=("A new-context login was observed.",),
        analyst_assessments=(
            "The sequence is consistent with possible misuse.",
        ),
        unresolved_questions=(
            "Was the login performed by the account owner?",
        ),
    )


def plan_probe_response(
    artefact: TelemetryArtefact,
    result: InvestigationResult,
) -> ResponsePlan:
    """Build a dry-run-only response plan for the probe finding."""
    finding = result.finding
    incident = Incident(
        id=_id(f"incident:{finding.id}"),
        opened_at=finding.created_at,
        updated_at=finding.created_at,
        title="Preliminary probe response",
        summary="Dry-run correlation record for the probe finding.",
        status=IncidentStatus.OPEN,
        severity=finding.severity,
        finding_ids=[finding.id],
        affected_entity_ids=[e.id for e in result.involved_entities],
    )
    account = next(
        (
            e
            for e in artefact.entities
            if e.entity_type is EntityType.ACCOUNT
        ),
        None,
    )
    actions = (
        ResponseAction(
            id=_id(f"action:{incident.id}:disable-account"),
            created_at=finding.created_at,
            incident_id=incident.id,
            target_entity_id=account.id if account is not None else None,
            name="disable-account",
            purpose="Suspend the probe account pending verification.",
            risk=ResponseRisk.HIGH,
            requires_approval=True,
            dry_run=True,
            status=ResponseStatus.PLANNED,
            verification_guidance="Confirm the account cannot authenticate.",
            supports_rollback=True,
            rollback_guidance="Re-enable only after ownership is verified.",
        ),
    )
    return ResponsePlan(
        incident=incident,
        finding=finding,
        groups=(
            ResponseActionGroup(
                category=ResponseCategory.CONTAINMENT,
                actions=actions,
            ),
        ),
    )


def validate_probe(artefact: TelemetryArtefact) -> ValidationSuiteResult:
    """Return a single passing validation case for the probe."""
    return ValidationSuiteResult(
        technique_id=_TECHNIQUE,
        cases=(
            ValidationCase(
                name="probe-corpus-unmodified",
                expected="1 finding",
                actual="1 finding",
                status=ValidationStatus.PASS,
                explanation="The unmodified probe corpus has the expected finding.",
            ),
        ),
    )


def report_probe(
    artefact: TelemetryArtefact,
    finding: Finding,
    result: InvestigationResult,
    plan: ResponsePlan,
    suite: ValidationSuiteResult,
) -> IncidentReport:
    """Aggregate the probe workflow into an incident report."""
    return IncidentReport(
        report_id=_id(f"report:{finding.id}"),
        generated_at=finding.created_at,
        finding=finding,
        involved_entities=result.involved_entities,
        timeline=result.timeline,
        evidence=result.evidence,
        confirmed_facts=result.confirmed_facts,
        analyst_assessments=result.analyst_assessments,
        unresolved_questions=result.unresolved_questions,
        plan=plan,
        suite=suite,
        executive_summary="A single finding consistent with possible misuse.",
        scope_summary="Covers the probe synthetic artefact only.",
        methodology=("Ran detection once.",),
        limitations=("Advisory and synthetic only.",),
        conclusion="No compromise asserted; response was not executed.",
    )


def probe_learning_path() -> LearningPath:
    """Return a minimal, deterministic probe learning path."""
    return LearningPath(
        technique_id=_TECHNIQUE,
        title="Probe Learning Path",
        description="A minimal path for the probe scenario.",
        steps=(
            LearningStep(
                id="orientation",
                ordinal=1,
                title="Orientation",
                objective=LearningObjective(
                    statement="Understand the probe scenario.",
                ),
                python_concepts=("Deterministic test data",),
                explanation="Walk through the minimal probe loop.",
                command_examples=("duke scenarios",),
                exercise=Exercise(
                    title="Inspect the artefact",
                    instructions="Run the probe loop and confirm a finding.",
                    expected_result="One finding at confidence 80.",
                    hints=(Hint(text="Start with simulation."),),
                    knowledge_check=KnowledgeCheck(
                        prompt="What is simulated?",
                        answer="Synthetic events only.",
                    ),
                ),
                safety_note="Reads only synthetic data.",
            ),
        ),
    )


def probe_registration() -> ScenarioRegistration:
    """Return the deterministic probe registration (test-only)."""
    return ScenarioRegistration(
        technique_id=_TECHNIQUE,
        slug="probe-observation",
        name="Probe Observation",
        aliases=("probe",),
        metadata_loader=probe_metadata_loader,
        capabilities=ScenarioCapabilities(
            simulation=generate_probe_simulation,
            detection=detect_probe,
            investigation=investigate_probe,
            response=plan_probe_response,
            validation=validate_probe,
            reporting=report_probe,
            learning=probe_learning_path,
        ),
    )


def probe_registry() -> ScenarioRegistry:
    """Return a fresh, isolated registry with only the probe registered."""
    registry = ScenarioRegistry()
    registry.register(probe_registration())
    return registry


__all__ = [
    "probe_learning_path",
    "probe_metadata_loader",
    "probe_registration",
    "probe_registry",
]
