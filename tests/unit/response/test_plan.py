"""Tests for the ResponsePlan response-plan model."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from duke.core import (
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    ResponseAction,
    ResponseRisk,
    ResponseStatus,
    Severity,
)
from duke.response import ResponseActionGroup, ResponseCategory, ResponsePlan

_WHEN = datetime(2026, 9, 22, 17, 12, tzinfo=UTC)


def _finding() -> Finding:
    return Finding(
        created_at=_WHEN,
        confidence=90,
        title="Compromised identity used from unfamiliar device",
        description="Suspicious behaviour sequence.",
        detection_name="compromised-identity-sequence",
        detection_details="Sequence details.",
        technique_id="T1078",
        severity=Severity.HIGH,
        status=FindingStatus.NEW,
    )


def _incident(finding: Finding) -> Incident:
    return Incident(
        opened_at=_WHEN,
        updated_at=_WHEN,
        title="Preliminary T1078 response",
        summary="Preliminary correlation record.",
        status=IncidentStatus.OPEN,
        severity=finding.severity,
        finding_ids=[finding.id],
        affected_entity_ids=[uuid4()],
    )


def _action(incident: Incident, name: str = "example-action") -> ResponseAction:
    return ResponseAction(
        created_at=_WHEN,
        incident_id=incident.id,
        name=name,
        purpose="If behaviour is possible misuse, take an example step.",
        risk=ResponseRisk.MEDIUM,
        requires_approval=True,
        dry_run=True,
        status=ResponseStatus.PLANNED,
        verification_guidance="Verify the example outcome.",
        supports_rollback=False,
    )


def _group(incident: Incident) -> ResponseActionGroup:
    return ResponseActionGroup(
        category=ResponseCategory.CONTAINMENT,
        actions=(_action(incident),),
    )


def test_response_plan_construction() -> None:
    finding = _finding()
    incident = _incident(finding)
    group = _group(incident)

    plan = ResponsePlan(incident=incident, finding=finding, groups=(group,))

    assert plan.actions() == group.actions
    assert plan.entity_ids() == ()


def test_actions_and_entity_ids_helpers() -> None:
    finding = _finding()
    incident = _incident(finding)
    incident.affected_entity_ids = []
    target = uuid4()
    action = _action(incident)
    action.target_entity_id = target
    group = ResponseActionGroup(
        category=ResponseCategory.RECOVERY,
        actions=(action,),
    )

    plan = ResponsePlan(incident=incident, finding=finding, groups=(group,))

    assert plan.actions() == (action,)
    assert plan.entity_ids() == (target,)


def test_json_round_trip() -> None:
    finding = _finding()
    incident = _incident(finding)
    plan = ResponsePlan(
        incident=incident, finding=finding, groups=(_group(incident),)
    )

    restored = ResponsePlan.model_validate_json(plan.model_dump_json())

    assert restored == plan


def test_unknown_field_rejected() -> None:
    finding = _finding()
    incident = _incident(finding)

    with pytest.raises(ValidationError):
        ResponsePlan(
            incident=incident,
            finding=finding,
            groups=(_group(incident),),
            extra="not allowed",
        )


def test_invalid_category_rejected() -> None:
    with pytest.raises(ValidationError):
        ResponseActionGroup(category="not-a-category", actions=())
