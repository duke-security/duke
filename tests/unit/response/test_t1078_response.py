"""Tests for dry-run T1078 response planning."""

from duke.core import IncidentStatus, ResponseStatus
from duke.detection import detect_t1078
from duke.investigation import investigate_t1078
from duke.response import (
    ResponseCategory,
    ResponsePlan,
    plan_t1078_response,
)
from duke.simulation import generate_t1078_simulation
from duke.telemetry import TelemetryArtefact

_CATEGORY_ORDER = (
    ResponseCategory.CONTAINMENT,
    ResponseCategory.EVIDENCE_PRESERVATION,
    ResponseCategory.INVESTIGATION_FOLLOWUP,
    ResponseCategory.RECOVERY,
)


def _fixture() -> tuple[TelemetryArtefact, ResponsePlan]:
    result = generate_t1078_simulation()
    artefact = TelemetryArtefact(entities=result.entities, events=result.events)
    finding = detect_t1078(artefact.events)[0]
    investigation = investigate_t1078(artefact, finding)
    return artefact, plan_t1078_response(artefact, investigation)


def _plan() -> ResponsePlan:
    return _fixture()[1]


def _action(name: str):
    for action in _plan().actions():
        if action.name == name:
            return action
    raise AssertionError(f"no action named {name!r}")


def test_groups_follow_the_four_category_order() -> None:
    plan = _plan()

    categories = tuple(group.category for group in plan.groups)
    assert categories == _CATEGORY_ORDER


def test_every_action_is_a_dry_run_proposal() -> None:
    plan = _plan()

    assert plan.actions()
    for action in plan.actions():
        assert action.dry_run is True
        assert action.requires_approval is True
        assert action.status is ResponseStatus.PLANNED
        assert action.purpose
        assert action.verification_guidance


def test_all_four_categories_are_populated() -> None:
    plan = _plan()

    for group in plan.groups:
        assert group.actions, f"category {group.category} has no actions"


def test_each_category_has_an_expected_action() -> None:
    plan = _plan()

    def names(category: ResponseCategory) -> set[str]:
        for group in plan.groups:
            if group.category is category:
                return {action.name for action in group.actions}
        return set()

    assert "disable-account" in names(ResponseCategory.CONTAINMENT)
    assert "preserve-telemetry-artefact" in names(
        ResponseCategory.EVIDENCE_PRESERVATION
    )
    assert "confirm-account-ownership" in names(
        ResponseCategory.INVESTIGATION_FOLLOWUP
    )
    assert "require-mfa-reauthentication" in names(ResponseCategory.RECOVERY)


def test_rollback_guidance_required_iff_reversible() -> None:
    plan = _plan()

    for action in plan.actions():
        if action.supports_rollback:
            assert action.rollback_guidance
        else:
            assert action.rollback_guidance is None


def test_rollback_semantics_disable_account() -> None:
    action = _action("disable-account")

    assert action.supports_rollback is True
    assert "ownership and access safety are verified" in action.rollback_guidance


def test_rollback_semantics_revoke_sessions_irreversible() -> None:
    action = _action("revoke-active-sessions")

    assert action.supports_rollback is False
    assert action.rollback_guidance is None
    assert "cannot be restored" in action.purpose


def test_rollback_semantics_deny_device_conditional_reallow() -> None:
    action = _action("deny-unfamiliar-device")

    assert action.supports_rollback is True
    assert "ownership and security posture are verified" in action.rollback_guidance


def test_rollback_semantics_preserved_evidence_not_deleted() -> None:
    action = _action("preserve-telemetry-artefact")

    assert action.supports_rollback is False
    assert action.rollback_guidance is None
    assert "delete" not in action.verification_guidance.lower()


def test_rollback_semantics_review_only_actions_have_no_rollback() -> None:
    for name in ("confirm-account-ownership", "review-privileged-access-grant"):
        action = _action(name)

        assert action.supports_rollback is False
        assert action.rollback_guidance is None


def test_rollback_semantics_mfa_never_weakens_baseline() -> None:
    action = _action("require-mfa-reauthentication")

    assert action.supports_rollback is True
    assert "baseline MFA requirements" in action.rollback_guidance


def test_rollback_semantics_rotate_never_restores_credentials() -> None:
    action = _action("rotate-account-credentials")

    assert action.supports_rollback is False
    assert action.rollback_guidance is None
    assert "never restore prior" in action.purpose.lower()


def test_every_action_explicitly_qualifies_its_claim() -> None:
    """No action asserts compromise or exfiltration as fact."""
    plan = _plan()
    disclaimers = (
        "not an assertion",
        "does not assume",
        "not a claim",
        "changes no system state",
        "pending verification",
        "cannot be restored",
        "cannot be altered",
        "only if",
    )

    for action in plan.actions():
        purpose = action.purpose.lower()
        assert any(
            disclaimer in purpose for disclaimer in disclaimers
        ), f"action {action.name} does not qualify its claim"


def test_containment_and_recovery_actions_are_conditional() -> None:
    """System-changing actions are conditional, not imperatives."""
    plan = _plan()
    conditional = {
        ResponseCategory.CONTAINMENT,
        ResponseCategory.RECOVERY,
    }

    for group in plan.groups:
        if group.category not in conditional:
            continue
        for action in group.actions:
            assert "if " in action.purpose.lower(), action.name


def test_incident_is_a_preliminary_correlation_record() -> None:
    plan = _plan()

    assert plan.incident.status is IncidentStatus.OPEN
    assert plan.incident.finding_ids == [plan.finding.id]
    assert all(action.incident_id == plan.incident.id for action in plan.actions())
    # Never asserts a confirmed compromise, exfiltration, or a final report.
    assert "preliminary" in plan.incident.summary.lower()
    assert "confirmed compromise" not in plan.incident.summary.lower()
    assert "exfiltration" not in plan.incident.summary.lower()


def test_target_entities_resolve_from_artefact() -> None:
    artefact, plan = _fixture()
    entities_by_id = {entity.id: entity for entity in artefact.entities}
    identifiers = {
        entities_by_id[entity_id].identifier
        for entity_id in plan.entity_ids()
        if entity_id in entities_by_id
    }

    assert "alex.morgan@example.lab" in identifiers
    assert "device-unknown-442" in identifiers
    assert identifiers <= {entity.identifier for entity in artefact.entities}


def test_output_is_deterministic() -> None:
    first = _plan()
    second = _plan()

    assert first == second
    assert first.actions() == second.actions()


def test_planner_has_no_filesystem_side_effects(tmp_path) -> None:
    before = set(tmp_path.rglob("*"))
    _fixture()
    assert set(tmp_path.rglob("*")) == before
