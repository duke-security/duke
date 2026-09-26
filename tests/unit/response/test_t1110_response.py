"""Tests for dry-run T1110 password-spraying response planning."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from duke.core import (
    Entity,
    EntityType,
    EventOutcome,
    Finding,
    FindingStatus,
    IncidentStatus,
    ResponseStatus,
    SecurityEvent,
    Severity,
)
from duke.detection import detect_t1110
from duke.investigation import InvestigationResult, investigate_t1110
from duke.response import (
    ResponseCategory,
    ResponsePlan,
    plan_t1110_response,
)
from duke.simulation import generate_t1110_simulation
from duke.telemetry import TelemetryArtefact

_CATEGORY_ORDER = (
    ResponseCategory.CONTAINMENT,
    ResponseCategory.EVIDENCE_PRESERVATION,
    ResponseCategory.INVESTIGATION_FOLLOWUP,
    ResponseCategory.RECOVERY,
)

SOURCE_IDENTIFIER = "host-198.51.100.77"
PORTAL_IDENTIFIER = "web-portal"
SUCCESS_ACCOUNT_IDENTIFIER = "svc.reports"

# Actions whose purpose is review / monitoring / evidence preservation and
# which may legitimately carry no target.
_NON_TARGETED = {
    "preserve-telemetry-artefact",
    "confirm-source-authorized",
    "review-sprayed-account-activity",
    "assess-failure-cause",
    "monitor-for-further-spray",
}


def _corpus() -> tuple[TelemetryArtefact, ResponsePlan, Finding]:
    sim = generate_t1110_simulation()
    artefact = TelemetryArtefact(entities=sim.entities, events=sim.events)
    finding = detect_t1110(artefact.events)[0]
    result = investigate_t1110(artefact, finding)
    return artefact, plan_t1110_response(artefact, result), finding


def _plan() -> ResponsePlan:
    return _corpus()[1]


def _names(plan: ResponsePlan) -> set[str]:
    return {action.name for action in plan.actions()}


def _actions(plan: ResponsePlan, name: str):
    return [a for a in plan.actions() if a.name == name]


def _entity(identifier: str, entity_type: EntityType) -> Entity:
    return Entity(
        id=uuid4(),
        entity_type=entity_type,
        identifier=identifier,
        display_name=identifier,
    )


def _synthetic_plan(
    *,
    actor_ids: tuple[str, ...],
    success_targets: tuple[str, ...],
    extra_host_identifier: str | None = None,
) -> ResponsePlan:
    """Build a deterministic synthetic spray finding and plan.

    ``actor_ids`` gives one ``actor_entity_id`` per failure event (the literal
    string "SOURCE" maps to the single real source id; any other distinct
    string becomes its own distinct UUID). ``success_targets`` names the
    accounts a referenced success event targets.
    """
    source_id = uuid4()
    source = _entity(SOURCE_IDENTIFIER, EntityType.HOST).model_copy(
        update={"id": source_id}
    )
    service = _entity(PORTAL_IDENTIFIER, EntityType.APPLICATION)
    acct_a = _entity("acct-a", EntityType.ACCOUNT)
    acct_b = _entity("acct-b", EntityType.ACCOUNT)
    acct_c = _entity("acct-c", EntityType.ACCOUNT)
    accounts_of = {"acct-a": acct_a, "acct-b": acct_b, "acct-c": acct_c}

    base = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    extra_hosts = (
        [_entity(extra_host_identifier, EntityType.HOST)]
        if extra_host_identifier is not None
        else []
    )

    # Each actor string yields a distinct actor id: "SOURCE" -> the real one.
    actor_id_of: dict[str, UUID] = {}

    def _resolve_actor(tag: str):
        if tag == "SOURCE":
            return source_id
        if tag not in actor_id_of:
            actor_id_of[tag] = uuid4()
        return actor_id_of[tag]

    failure_events = []
    for index, tag in enumerate(actor_ids):
        failure_events.append(
            SecurityEvent(
                id=uuid4(),
                occurred_at=base,
                action="authenticate",
                outcome=EventOutcome.FAILURE,
                source="identity_provider",
                actor_entity_id=_resolve_actor(tag),
                target_entity_ids=[
                    service.id,
                    accounts_of["acct-a" if index % 2 == 0 else "acct-b"].id,
                ],
            )
        )
    success_events = [
        SecurityEvent(
            id=uuid4(),
            occurred_at=base,
            action="authenticate",
            outcome=EventOutcome.SUCCESS,
            source="identity_provider",
            actor_entity_id=source_id,
            target_entity_ids=[
                service.id,
                accounts_of[name].id,
            ],
        )
        for name in success_targets
    ]

    events = tuple(failure_events + success_events)
    involved = (source, acct_a, acct_b)

    finding = Finding(
        id=uuid4(),
        created_at=base,
        title="synthetic",
        description="synthetic",
        detection_name="test-rule",
        detection_details="synthetic",
        technique_id="T1110",
        severity=Severity.HIGH,
        status=FindingStatus.NEW,
        confidence=80,
        event_ids=[e.id for e in events],
        entity_ids=[e.id for e in involved],
    )

    artifact_entities = (
        source,
        service,
        acct_a,
        acct_b,
        acct_c,
        *extra_hosts,
    )
    artefact = TelemetryArtefact(
        entities=artifact_entities,
        events=events,
    )
    result = InvestigationResult(
        finding=finding,
        involved_entities=involved,
        evidence=(),
        timeline=(),
        confirmed_facts=(),
        analyst_assessments=(),
        unresolved_questions=(),
    )
    return plan_t1110_response(artefact, result)


# ---- corpus plan structure --------------------------------------------------


def test_groups_follow_the_four_category_order() -> None:
    plan = _plan()
    assert tuple(group.category for group in plan.groups) == _CATEGORY_ORDER


def test_all_four_categories_are_present_in_corpus() -> None:
    plan = _plan()
    assert len(plan.groups) == 4
    for group in plan.groups:
        assert group.actions  # populated for the corpus


def test_every_action_is_a_dry_run_proposal() -> None:
    plan = _plan()
    assert plan.actions()
    for action in plan.actions():
        assert action.dry_run is True
        assert action.requires_approval is True
        assert action.status is ResponseStatus.PLANNED
        assert action.purpose
        assert action.verification_guidance


def test_expected_actions_are_present_in_corpus() -> None:
    plan = _plan()
    names = _names(plan)
    assert "temporarily-rate-limit-source" in names
    assert "revoke-active-sessions" in names
    assert "preserve-telemetry-artefact" in names
    assert "confirm-source-authorized" in names
    assert "review-sprayed-account-activity" in names
    assert "assess-failure-cause" in names
    assert "monitor-for-further-spray" in names
    assert "apply-temporary-step-up-authentication" in names
    assert "rotate-account-credentials" in names


def test_rollback_guidance_required_iff_reversible() -> None:
    plan = _plan()
    for action in plan.actions():
        if action.supports_rollback:
            assert action.rollback_guidance
        else:
            assert action.rollback_guidance is None


# ---- rollback semantics (correction 10) --------------------------------------


def test_rollback_semantics_source_throttle_reversible() -> None:
    action = _actions(_plan(), "temporarily-rate-limit-source")[0]
    assert action.supports_rollback is True
    assert "must not weaken existing controls" in action.rollback_guidance


def test_rollback_semantics_session_revocation_irreversible() -> None:
    action = _actions(_plan(), "revoke-active-sessions")[0]
    assert action.supports_rollback is False
    assert action.rollback_guidance is None
    assert "cannot be restored" in action.purpose


def test_rollback_semantics_evidence_never_deleted() -> None:
    action = _actions(_plan(), "preserve-telemetry-artefact")[0]
    assert action.supports_rollback is False
    assert action.rollback_guidance is None
    assert "never be deleted" in action.verification_guidance


def test_step_up_is_temporary_reversible_never_weakens_baseline() -> None:
    action = _actions(_plan(), "apply-temporary-step-up-authentication")[0]
    # Clearly a temporary, reversible policy change.
    assert action.supports_rollback is True
    assert "temporary" in action.purpose
    assert "does not weaken the organization's baseline" in action.rollback_guidance


def test_rollback_semantics_rotation_never_restores_credentials() -> None:
    action = _actions(_plan(), "rotate-account-credentials")[0]
    assert action.supports_rollback is False
    assert action.rollback_guidance is None
    assert "Never restore prior" in action.purpose


def test_review_and_monitoring_have_no_rollback() -> None:
    plan = _plan()
    for action in plan.actions():
        if action.name in (
            "confirm-source-authorized",
            "review-sprayed-account-activity",
            "assess-failure-cause",
            "monitor-for-further-spray",
        ):
            assert action.supports_rollback is False
            assert action.rollback_guidance is None


def test_containment_and_recovery_are_conditional() -> None:
    plan = _plan()
    for group in plan.groups:
        if group.category not in (
            ResponseCategory.CONTAINMENT,
            ResponseCategory.RECOVERY,
        ):
            continue
        for action in group.actions:
            assert "if" in action.purpose.lower(), action.name


# ---- cautious language (correction 7) ----------------------------------------


def test_no_affirmative_unqualified_claims() -> None:
    plan = _plan()
    text = (
        " "
        + " ".join(
            [plan.incident.summary]
            + [a.purpose for a in plan.actions()]
            + [a.verification_guidance for a in plan.actions()]
        ).lower()
        + " "
    )

    assert "compromise is not confirmed" in text
    assert "suspected password-spraying behaviour" in text

    for affirmative in (
        "is compromised",
        "has been compromised",
        "confirmed compromise",
        "the attacker",
        "is malicious",
        "stole credentials",
        "impact occurred",
        "intrusion succeeded",
        "valid credential was used",
    ):
        assert affirmative not in text, f"affirmative claim present: {affirmative!r}"


# ---- incident ----------------------------------------------------------------


def test_incident_is_a_preliminary_correlation_record() -> None:
    plan = _plan()
    assert plan.incident.status is IncidentStatus.OPEN
    assert plan.incident.finding_ids == [plan.finding.id]
    assert all(action.incident_id == plan.incident.id for action in plan.actions())
    assert "preliminary" in plan.incident.title.lower()
    assert "not confirmed" in plan.incident.summary.lower()


def test_incident_affected_entities_are_nonempty() -> None:
    plan = _plan()
    assert plan.incident.affected_entity_ids


# ---- source resolution (correction 1) ----------------------------------------


def test_corpus_source_is_actor_and_portal_not_targeted() -> None:
    artefact, plan, _ = _corpus()
    id_to_identifier = {e.id: e.identifier for e in artefact.entities}
    identifiers = {
        id_to_identifier[i] for i in plan.entity_ids() if i in id_to_identifier
    }
    assert SOURCE_IDENTIFIER in identifiers
    assert PORTAL_IDENTIFIER not in identifiers


def test_multiple_actor_ids_omit_source_containment_and_mark_incomplete() -> None:
    plan = _synthetic_plan(actor_ids=("A1", "A2"), success_targets=())
    names = _names(plan)
    assert "temporarily-rate-limit-source" not in names
    assert "incomplete or ambiguous" in plan.incident.summary


def test_no_actor_ids_omit_source_containment() -> None:
    plan = _synthetic_plan(actor_ids=(), success_targets=())
    assert "temporarily-rate-limit-source" not in _names(plan)


def test_unrelated_host_is_not_chosen_as_source() -> None:
    """With a consistent single actor present plus an unrelated HOST in the
    in-scope entities, the actor (SOURCE) is the source, not the unrelated
    host."""
    plan = _synthetic_plan(
        actor_ids=("SOURCE", "SOURCE"),
        success_targets=(),
        extra_host_identifier="unrelated-host",
    )
    rate = _actions(plan, "temporarily-rate-limit-source")
    assert len(rate) == 1
    target_id = rate[0].target_entity_id
    assert target_id is not None


# ---- success-account resolution (correction 2) -------------------------------


def test_success_account_is_svc_reports_in_corpus() -> None:
    artefact, plan, _ = _corpus()
    id_to_identifier = {e.id: e.identifier for e in artefact.entities}
    rec = _actions(plan, "rotate-account-credentials")
    assert rec and rec[0].target_entity_id is not None
    assert id_to_identifier.get(rec[0].target_entity_id) == SUCCESS_ACCOUNT_IDENTIFIER


def test_zero_success_targets_omit_recovery_actions() -> None:
    plan = _synthetic_plan(actor_ids=("SOURCE", "SOURCE"), success_targets=())
    names = _names(plan)
    assert "rotate-account-credentials" not in names
    assert "apply-temporary-step-up-authentication" not in names
    assert "revoke-active-sessions" not in names


def test_multiple_success_targets_omit_recovery_actions() -> None:
    plan = _synthetic_plan(
        actor_ids=("SOURCE", "SOURCE"),
        success_targets=("acct-a", "acct-b"),
    )
    names = _names(plan)
    assert "rotate-account-credentials" not in names
    assert "apply-temporary-step-up-authentication" not in names


def test_single_success_target_enables_recovery_actions() -> None:
    plan = _synthetic_plan(
        actor_ids=("SOURCE", "SOURCE"),
        success_targets=("acct-a",),
    )
    rec = _actions(plan, "rotate-account-credentials")
    assert rec and rec[0].target_entity_id is not None


# ---- targeted actions never carry a None target (correction 3) ---------------


def test_no_targeted_action_has_none_target() -> None:
    plan = _plan()
    for action in plan.actions():
        if action.name in _NON_TARGETED:
            continue
        assert action.target_entity_id is not None, action.name


def test_all_four_categories_present_when_targets_ambiguous() -> None:
    plan = _synthetic_plan(actor_ids=("A1", "A2"), success_targets=())
    categories = [group.category for group in plan.groups]
    assert categories == list(_CATEGORY_ORDER)


# ---- determinism & side effects ----------------------------------------------


def test_output_is_deterministic() -> None:
    first = _plan()
    second = _plan()
    assert first == second
    assert first.actions() == second.actions()
    assert len({a.id for a in first.actions()}) == len(first.actions())


def test_planner_has_no_side_effects(tmp_path, monkeypatch) -> None:
    import socket
    import subprocess

    def _raise(*_a, **_k):
        raise AssertionError("planner performed side-effecting activity")

    monkeypatch.setattr(socket, "socket", _raise)
    monkeypatch.setattr(subprocess, "Popen", _raise)
    monkeypatch.setattr(subprocess, "run", _raise)
    monkeypatch.chdir(tmp_path)
    before = {p for p in tmp_path.rglob("*")}

    _plan()

    assert {p for p in tmp_path.rglob("*")} == before
