"""Deterministic incident reporting for the T1110.003 Password Spraying scenario.

``report_t1110`` aggregates the existing workflow data — the telemetry
artefact, the ``Finding``, the evidence-led ``InvestigationResult``, the
dry-run ``ResponsePlan``, and the ``ValidationSuiteResult`` — into a
deterministic :class:`IncidentReport` for the shared Markdown renderer. It
never regenerates telemetry, never reruns detection/investigation/response/
validation, never modifies the source artefact, never executes a response
action, and never asserts a confirmed compromise, credential theft,
attribution, successful intrusion, or impact.

Entity roles are derived deterministically and safely (never from fixed
UUIDs, names, IPs, list position, or corpus literals): the source comes from
the unique finding-referenced actor; accounts from finding-scoped
``EntityType.ACCOUNT`` entities; a uniquely-resolved success-associated
account is noted without erasing the safe sprayed-account base; contextual
authentication services are never labelled as sprayed accounts; and anything
unclassifiable renders as ``involved entity``.
"""

from uuid import UUID, uuid5

from duke.core import (
    Entity,
    EntityType,
    EventOutcome,
    Finding,
    SecurityEvent,
)
from duke.investigation import InvestigationResult
from duke.reporting.result import IncidentReport
from duke.response import ResponsePlan
from duke.telemetry import TelemetryArtefact
from duke.validation import ValidationSuiteResult

# Deterministic namespace so report identifiers are repeatable for the same
# finding, mirroring the stable IDs used by earlier pipeline stages.
_REPORT_NAMESPACE = UUID("1110e000-0000-4000-8000-000000000000")

_TECHNIQUE_ID = "T1110"
_TECHNIQUE_LABEL = "password spraying (MITRE ATT&CK T1110.003)"
_REPORT_TITLE = "T1110 Incident Report"
_REPORT_TECHNIQUE_LABEL = "Brute Force: Password Spraying"
_INVOLVED_INTRO = (
    "The source host and the distinct sprayed accounts implicated by the "
    "spray finding. A shared authentication service, if present, is context "
    "and is never treated as a sprayed account."
)

ROLE_SOURCE = "source"
ROLE_ACCOUNT = "sprayed account"
ROLE_SUCCESS_ACCOUNT = "sprayed account; later success observed"
ROLE_INVOLVED = "involved entity"


def _referenced(
    artefact: TelemetryArtefact, finding: Finding
) -> list[SecurityEvent]:
    event_ids = set(finding.event_ids)
    return [event for event in artefact.events if event.id in event_ids]


def _referenced_source_id(
    artefact: TelemetryArtefact,
    finding: Finding,
    involved_entity_ids: set[UUID],
) -> UUID | None:
    """The unique finding-referenced actor that is also an involved entity."""
    actor_ids: set[UUID] = set()
    for event in _referenced(artefact, finding):
        actor = event.actor_entity_id
        if actor is not None and actor in involved_entity_ids:
            actor_ids.add(actor)
    if len(actor_ids) != 1:
        return None
    return next(iter(actor_ids))


def _success_account_id(
    artefact: TelemetryArtefact,
    finding: Finding,
    involved_entity_ids: set[UUID],
    entities: dict[UUID, Entity],
) -> UUID | None:
    """The uniquely-resolved finding-scoped ACCOUNT target of a referenced
    successful authentication, if exactly one unambiguous account exists."""
    candidates: set[UUID] = set()
    for event in _referenced(artefact, finding):
        if event.outcome is not EventOutcome.SUCCESS:
            continue
        for target_id in event.target_entity_ids:
            entity = entities.get(target_id)
            if (
                entity is not None
                and entity.entity_type is EntityType.ACCOUNT
                and target_id in involved_entity_ids
            ):
                candidates.add(target_id)
    if len(candidates) != 1:
        return None
    return next(iter(candidates))


def _executive_summary(finding: Finding, suite: ValidationSuiteResult) -> str:
    return (
        "Behaviour-based detection identified a suspicious password-spraying "
        "pattern: a single source performed unsuccessful authentications "
        f"against several distinct accounts inside a bounded window, at a "
        f"confidence of {finding.confidence}/100. A referenced later success, "
        "if present, is supporting behaviour consistent with possible "
        "credential validation — not proof of compromise. Malicious intent, "
        "credential theft, attribution, successful intrusion, and impact are "
        "not confirmed. All "
        f"{len(suite.cases)} detection-validation cases passed before this "
        "report was produced. The proposed response is dry-run-only and "
        "approval-gated; nothing was executed."
    )


def _scope_summary(artefact: TelemetryArtefact, finding: Finding) -> str:
    return (
        "This report covers the exported normalized telemetry artefact for the "
        f"{_TECHNIQUE_ID} scenario: {len(artefact.events)} security events "
        f"across {len(artefact.entities)} synthetic entities, centred on the "
        f"single detection finding ({finding.detection_name}). It compiles the "
        "finding, its supporting evidence, the chronological timeline, the "
        "evidence-led investigation, the dry-run response plan, and the "
        "detection-validation result. Only synthetic data are involved; no live "
        "system, account, session, permission, file, network, or security "
        "control was accessed or modified, and no response action was executed."
    )


_METHODOLOGY = (
    "Loaded the artefact with load_telemetry_artefact; no telemetry was "
    "regenerated.",
    "Ran behaviour-based detection (detect_t1110) and asserted exactly one "
    "finding.",
    "Ran the evidence-led investigation (investigate_t1110) across the finding's "
    "referenced events.",
    "Ran deterministic response planning (plan_t1110_response) producing "
    "dry-run-only, approval-gated actions grouped by category.",
    "Ran detection validation (validate_t1110) exactly once; the suite must pass "
    "before reporting.",
    "Rendered this deterministic Markdown report from the workflow data above.",
)

_LIMITATIONS = (
    "This report is advisory and derived from synthetic, disposable data in an "
    "isolated lab; it is not a confirmed incident or a final incident report.",
    "It does not assert that an account was compromised, that credentials were "
    "stolen, that malicious intent existed, or that any impact occurred.",
    "A later successful authentication is consistent with possible credential "
    "validation but is not proof of compromise.",
    "Impact, attribution, and account state are unresolved questions, not "
    "established facts.",
    "Response actions are recommendations only: they are dry-run, approval-"
    "required, and were not executed.",
    "Validation asserts internal consistency of Duke's detection rule against "
    "its own corpus and mutations, not real-world precision or recall.",
    "The report timestamp is the deterministic detection timestamp "
    "(finding.created_at), not the wall-clock export time.",
)


def _conclusion(finding: Finding, suite: ValidationSuiteResult) -> str:
    return (
        f"The observables are consistent with suspected {_TECHNIQUE_LABEL} at "
        f"confidence {finding.confidence}/100, and all {len(suite.cases)} "
        "detection-validation cases passed. This remains an analytic "
        "assessment: malicious intent, credential theft, compromise, "
        "attribution, successful intrusion, and impact are not confirmed, and "
        "no response action was executed. If further investigation supports "
        "misuse, follow the approval-gated, dry-run response recommendations to "
        "preserve evidence and to contain and recover."
    )


def report_t1110(
    artefact: TelemetryArtefact,
    finding: Finding,
    result: InvestigationResult,
    plan: ResponsePlan,
    suite: ValidationSuiteResult,
) -> IncidentReport:
    """Aggregate workflow data into a deterministic :class:`IncidentReport`."""
    involved = list(result.involved_entities)
    entities_by_id = {entity.id: entity for entity in artefact.entities}
    involved_ids = {entity.id for entity in involved}

    source_id = _referenced_source_id(artefact, finding, involved_ids)
    success_id = _success_account_id(
        artefact, finding, involved_ids, entities_by_id
    )

    roles: list[str] = []
    for entity in involved:
        if entity.id == source_id:
            roles.append(ROLE_SOURCE)
        elif entity.entity_type is EntityType.ACCOUNT:
            if entity.id == success_id:
                roles.append(ROLE_SUCCESS_ACCOUNT)
            else:
                roles.append(ROLE_ACCOUNT)
        else:
            roles.append(ROLE_INVOLVED)

    return IncidentReport(
        report_id=uuid5(_REPORT_NAMESPACE, f"report:{finding.id}"),
        generated_at=finding.created_at,
        finding=finding,
        involved_entities=tuple(involved),
        entity_roles=tuple(roles),
        involved_entities_intro=_INVOLVED_INTRO,
        timeline=result.timeline,
        evidence=result.evidence,
        confirmed_facts=result.confirmed_facts,
        analyst_assessments=result.analyst_assessments,
        unresolved_questions=result.unresolved_questions,
        plan=plan,
        suite=suite,
        title=_REPORT_TITLE,
        technique_label=_REPORT_TECHNIQUE_LABEL,
        executive_summary=_executive_summary(finding, suite),
        scope_summary=_scope_summary(artefact, finding),
        methodology=_METHODOLOGY,
        limitations=_LIMITATIONS,
        conclusion=_conclusion(finding, suite),
    )
