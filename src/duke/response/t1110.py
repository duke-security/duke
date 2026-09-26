"""Dry-run response planning for the T1110.003 Password Spraying scenario.

``plan_t1110_response`` consumes an existing :class:`InvestigationResult`
(which itself wraps the telemetry artefact and the ``Finding`` produced by
detection) and turns it into a deterministic :class:`ResponsePlan`. The plan
correlates the finding into a *preliminary* :class:`Incident` record — a
record required so each :class:`ResponseAction` can carry an ``incident_id``
— and groups proposed, dry-run-only actions by category: immediate
containment, evidence preservation, investigation follow-up, and recovery.

Everything here is a *conditional, approval-gated proposal*. No action is
ever executed: every proposed action is ``dry_run=True``,
``requires_approval=True``, and ``status=PLANNED``, and there is no code path
that contacts an identity provider, device, network, file system, or security
control.

Target selection is strictly evidence-led and bounded by the finding and the
investigation result:

- The **source** is the unique ``actor_entity_id`` across events referenced
  by ``finding.event_ids``, resolved against ``result.involved_entities``.
  If there is not exactly one consistent, resolved source, source-targeted
  containment is omitted and the plan records incomplete/ambiguous context.
- The **success-associated account** is the uniquely resolved, finding-scoped
  ``EntityType.ACCOUNT`` target of a referenced successful authentication.
  If there is not exactly one unambiguous account, session revocation,
  credential rotation, and account-specific step-up actions are omitted.
- Targeted containment/recovery actions are never emitted with
  ``target_entity_id=None``; review, monitoring, and evidence-preservation
  actions may legitimately carry no target.

Wording is cautious throughout: suspected password-spraying behaviour and
possible credential validation are referenced, never confirmed compromise,
attribution, impact, or malicious intent.
"""

from uuid import UUID, uuid5

from duke.core import (
    Entity,
    EntityType,
    EventOutcome,
    Finding,
    Incident,
    IncidentStatus,
    ResponseAction,
    ResponseRisk,
    ResponseStatus,
    SecurityEvent,
)
from duke.investigation import InvestigationResult
from duke.response.plan import (
    ResponseActionGroup,
    ResponseCategory,
    ResponsePlan,
)
from duke.telemetry import TelemetryArtefact

# Deterministic namespace so incident and action identifiers are repeatable
# for the same finding, mirroring the stable IDs used by simulation,
# detection, and investigation.
_RESPONSE_NAMESPACE = UUID("1110c000-0000-4000-8000-000000000000")


def _build_action(
    incident: Incident,
    finding: Finding,
    name: str,
    purpose: str,
    verification: str,
    risk: ResponseRisk,
    *,
    target: Entity | None,
    supports_rollback: bool,
    rollback_guidance: str | None,
) -> ResponseAction:
    """Construct one deterministic, dry-run-only proposed action."""
    return ResponseAction(
        id=uuid5(_RESPONSE_NAMESPACE, f"{incident.id}:{name}"),
        created_at=finding.created_at,
        incident_id=incident.id,
        target_entity_id=target.id if target is not None else None,
        name=name,
        purpose=purpose,
        risk=risk,
        requires_approval=True,
        dry_run=True,
        status=ResponseStatus.PLANNED,
        verification_guidance=verification,
        supports_rollback=supports_rollback,
        rollback_guidance=rollback_guidance,
    )


def _referenced_events(
    artefact: TelemetryArtefact,
    finding: Finding,
) -> tuple[SecurityEvent, ...]:
    """Return artefact events referenced by ``finding.event_ids`` (sole
    event-selection boundary)."""
    event_ids = set(finding.event_ids)
    return tuple(event for event in artefact.events if event.id in event_ids)


def _resolve_source(
    artefact: TelemetryArtefact,
    finding: Finding,
    involved_by_id: dict[UUID, Entity],
) -> Entity | None:
    """Resolve the source from referenced events' actor IDs, intersected with
    the investigated entities. Returns ``None`` unless there is exactly one
    consistent, resolved source actor."""
    actor_ids = {
        event.actor_entity_id
        for event in _referenced_events(artefact, finding)
        if event.actor_entity_id is not None
    }
    if len(actor_ids) != 1:
        return None
    return involved_by_id.get(next(iter(actor_ids)))


def _resolve_success_account(
    artefact: TelemetryArtefact,
    finding: Finding,
    involved_by_id: dict[UUID, Entity],
    entities_by_id: dict[UUID, Entity],
) -> Entity | None:
    """Resolve the uniquely associated success-account, or ``None``.

    A candidate is a target of a finding-referenced successful authentication
    that is present in the investigated entities and classified as an account.
    Any number other than one unambiguous account yields ``None``.
    """
    success_ids: set[UUID] = set()
    for event in _referenced_events(artefact, finding):
        if event.outcome is not EventOutcome.SUCCESS:
            continue
        for target_id in event.target_entity_ids:
            entity = entities_by_id.get(target_id)
            if entity is None:
                continue
            if (
                entity.entity_type is EntityType.ACCOUNT
                and target_id in involved_by_id
            ):
                success_ids.add(target_id)
    if len(success_ids) != 1:
        return None
    return entities_by_id.get(next(iter(success_ids)))


def _containment_actions(
    incident: Incident,
    finding: Finding,
    source: Entity | None,
    success_account: Entity | None,
) -> tuple[ResponseAction, ...]:
    """Proposed immediate-containment actions (conditional recommendations).

    Targeted containment is only emitted when its target is fully resolved;
    it is never emitted with ``target_entity_id=None``."""

    def _source_limit() -> tuple[ResponseAction, ...]:
        if source is None:
            return ()
        return (
            _build_action(
                incident,
                finding,
                name="temporarily-rate-limit-source",
                purpose=(
                    "If the source is not first confirmed to be authorized "
                    "infrastructure (a shared NAT, proxy, authorized "
                    "scanner, identity provider, or corporate egress "
                    "point), apply a temporary authentication rate limit "
                    "or challenge to this source to slow further attempts "
                    "pending human verification. This is deliberately "
                    "temporary and never an unconditional permanent block; "
                    "it is a recommendation, not an assertion that the "
                    "source is hostile."
                ),
                verification=(
                    "Confirm the temporary limit or challenge is in effect "
                    "for this source and that unintended back-to-back "
                    "attempts slow or stop. Note that a quiet period alone "
                    "is not proof the source is benign."
                ),
                risk=ResponseRisk.MEDIUM,
                target=source,
                supports_rollback=True,
                rollback_guidance=(
                    "Remove the temporary limit or challenge only after the "
                    "source is confirmed authorized or benign; removal must "
                    "not weaken existing controls or leave suspected "
                    "accounts without required protections."
                ),
            ),
        )

    def _revoke_sessions() -> tuple[ResponseAction, ...]:
        if success_account is None:
            return ()
        return (
            _build_action(
                incident,
                finding,
                name="revoke-active-sessions",
                purpose=(
                    "If human review identifies the sessions on the "
                    "success-associated account as unauthorized or "
                    "sufficiently suspicious, invalidate those sessions so "
                    "they cannot remain active. Revoked sessions cannot be "
                    "restored; review is required before any approval."
                ),
                verification=(
                    "Confirm, after human review, that no active sessions "
                    "remain for the success-associated account."
                ),
                risk=ResponseRisk.MEDIUM,
                target=success_account,
                supports_rollback=False,
                rollback_guidance=None,
            ),
        )

    return _source_limit() + _revoke_sessions()


def _evidence_actions(
    incident: Incident,
    finding: Finding,
) -> tuple[ResponseAction, ...]:
    """Proposed evidence-preservation action (no target required)."""
    return (
        _build_action(
            incident,
            finding,
            name="preserve-telemetry-artefact",
            purpose=(
                "Retain an immutable copy and a recorded hash of the "
                "exported telemetry artefact so the supporting evidence "
                "cannot be altered before investigation concludes."
            ),
            verification=(
                "Confirm a verified copy and its digest are recorded and "
                "readable; preserved evidence must never be deleted as a "
                "rollback."
            ),
            risk=ResponseRisk.LOW,
            target=None,
            supports_rollback=False,
            rollback_guidance=None,
        ),
    )


def _investigation_actions(
    incident: Incident,
    finding: Finding,
    source: Entity | None,
) -> tuple[ResponseAction, ...]:
    """Proposed investigation follow-up actions (review/monitoring)."""
    return (
        _build_action(
            incident,
            finding,
            name="confirm-source-authorized",
            purpose=(
                "Engage the network or identity team to determine whether "
                "the source is authorized infrastructure (a shared NAT, "
                "proxy, authorized scanner, identity provider, or corporate "
                "egress point). Reviewing this changes no system state and "
                "is not a claim that the source is hostile."
            ),
            verification=(
                "Record whether the source is confirmed authorized or "
                "whether it remains explainable only by the suspected "
                "spraying behaviour."
            ),
            risk=ResponseRisk.LOW,
            target=source,
            supports_rollback=False,
            rollback_guidance=None,
        ),
        _build_action(
            incident,
            finding,
            name="review-sprayed-account-activity",
            purpose=(
                "Review subsequent activity for the finding-scoped accounts "
                "to determine whether any showed further suspicious "
                "behaviour after the failed attempts. Review changes no "
                "system state."
            ),
            verification=(
                "Document whether any affected account showed follow-on "
                "activity beyond the observed failed authentications."
            ),
            risk=ResponseRisk.LOW,
            target=None,
            supports_rollback=False,
            rollback_guidance=None,
        ),
        _build_action(
            incident,
            finding,
            name="assess-failure-cause",
            purpose=(
                "Determine whether the observed failures reflect user "
                "error, automation, or hostile activity. This is analysis; "
                "intent is not asserted."
            ),
            verification=(
                "Document the most plausible explanation and any evidence "
                "for or against hostile intent."
            ),
            risk=ResponseRisk.LOW,
            target=None,
            supports_rollback=False,
            rollback_guidance=None,
        ),
        _build_action(
            incident,
            finding,
            name="monitor-for-further-spray",
            purpose=(
                "Monitor for the source continuing attempted "
                "authentications outside the detection window or appearing "
                "through other egress points. Monitoring changes no system "
                "state."
            ),
            verification=(
                "Review monitoring for renewed attempts; absence of further "
                "alerts is not, by itself, proof that the behaviour has "
                "stopped."
            ),
            risk=ResponseRisk.LOW,
            target=None,
            supports_rollback=False,
            rollback_guidance=None,
        ),
    )


def _recovery_actions(
    incident: Incident,
    finding: Finding,
    success_account: Entity | None,
) -> tuple[ResponseAction, ...]:
    """Proposed recovery recommendations (conditional, for the verified
    success-associated account only; never emitted without a resolved
    target)."""
    if success_account is None:
        return ()
    return (
        _build_action(
            incident,
            finding,
            name="apply-temporary-step-up-authentication",
            purpose=(
                "If one success-associated account is verified and approved "
                "by a human, apply a clearly temporary, reversible step-up "
                "authentication challenge to that account (for example an "
                "additional MFA or re-verification step). This is a "
                "temporary policy change, not a permanent weakening of "
                "security."
            ),
            verification=(
                "Confirm the temporary step-up challenge is applied to the "
                "account and that the owner can authenticate through it."
            ),
            risk=ResponseRisk.MEDIUM,
            target=success_account,
            supports_rollback=True,
            rollback_guidance=(
                "The prior policy may be restored only after explicit "
                "review and only if doing so does not weaken the "
                "organization's baseline MFA or security requirements."
            ),
        ),
        _build_action(
            incident,
            finding,
            name="rotate-account-credentials",
            purpose=(
                "Rotate the success-associated account's credentials only if "
                "a human verifies ownership and determines the account was "
                "affected. Never restore prior potentially exposed "
                "credentials."
            ),
            verification=(
                "Confirm the owner can authenticate with new credentials "
                "and that the prior credentials no longer work."
            ),
            risk=ResponseRisk.HIGH,
            target=success_account,
            supports_rollback=False,
            rollback_guidance=None,
        ),
    )


def plan_t1110_response(
    artefact: TelemetryArtefact,
    result: InvestigationResult,
) -> ResponsePlan:
    """Build a deterministic, dry-run-only response plan from an investigation.

    The plan correlates ``result.finding`` into a preliminary ``Incident``
    (solely to give each ``ResponseAction`` an ``incident_id``) and proposes
    actions grouped by category. The incident is a deterministic correlation
    record, not a confirmation of compromise, attribution, impact, or a final
    incident report.
    """
    finding = result.finding
    involved = list(result.involved_entities)
    involved_by_id = {entity.id: entity for entity in involved}
    entities_by_id = {entity.id: entity for entity in artefact.entities}

    source = _resolve_source(artefact, finding, involved_by_id)
    success_account = _resolve_success_account(
        artefact, finding, involved_by_id, entities_by_id
    )

    # --- incomplete / ambiguous context detection (events + entities) ------
    referenced_event_ids = {
        event.id
        for event in _referenced_events(artefact, finding)
    }
    unresolved_event_count = len(finding.event_ids) - len(referenced_event_ids)
    unresolved_entity_count = len(finding.entity_ids) - len(involved_by_id)

    had_success = any(
        event.outcome is EventOutcome.SUCCESS
        for event in _referenced_events(artefact, finding)
    )
    success_ambiguous = had_success and success_account is None

    incomplete_context = bool(
        unresolved_event_count
        or unresolved_entity_count
        or not result.evidence
        or source is None
        or success_ambiguous
    )

    summary = (
        "Preliminary correlation record grouping the T1110 finding for "
        "response planning. It records correlation only: suspected "
        "password-spraying behaviour may have occurred, but compromise is "
        "not confirmed, and attribution, impact, and malicious intent are "
        "not asserted."
    )
    if incomplete_context:
        summary += (
            " Response was planned against incomplete or ambiguous "
            "investigation context: some events, entities, the source, or "
            "the success-associated account could not be resolved uniquely."
        )

    incident = Incident(
        id=uuid5(_RESPONSE_NAMESPACE, f"incident:{finding.id}"),
        opened_at=finding.created_at,
        updated_at=finding.created_at,
        title="Preliminary T1110 password-spraying response",
        summary=summary,
        status=IncidentStatus.OPEN,
        severity=finding.severity,
        finding_ids=[finding.id],
        affected_entity_ids=[entity.id for entity in involved],
    )

    groups = (
        ResponseActionGroup(
            category=ResponseCategory.CONTAINMENT,
            actions=_containment_actions(incident, finding, source, success_account),
        ),
        ResponseActionGroup(
            category=ResponseCategory.EVIDENCE_PRESERVATION,
            actions=_evidence_actions(incident, finding),
        ),
        ResponseActionGroup(
            category=ResponseCategory.INVESTIGATION_FOLLOWUP,
            actions=_investigation_actions(incident, finding, source),
        ),
        ResponseActionGroup(
            category=ResponseCategory.RECOVERY,
            actions=_recovery_actions(incident, finding, success_account),
        ),
    )

    return ResponsePlan(incident=incident, finding=finding, groups=groups)
