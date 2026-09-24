"""Typed objects describing a proposed, dry-run-only response plan.

A :class:`ResponsePlan` is a *proposal*: it correlates a ``Finding``
into a deterministic preliminary ``Incident`` record and lists the
``ResponseAction`` records that a human might take. Nothing in this
package executes an action against a real system. Every action is
flagged ``dry_run=True``, ``requires_approval=True``, and
``status=PLANNED``; there is no execution engine here, so a plan can
never modify a real account, session, permission, file, network, or
security control.
"""

from enum import StrEnum
from uuid import UUID

from pydantic import Field

from duke.core import Finding, Incident, ResponseAction
from duke.core._base import DukeModel


class ResponseCategory(StrEnum):
    """The role an action plays within a full response plan.

    Actions are grouped by category so a plan reads in a deliberate
    order: contain first, preserve evidence, investigate, then
    recommend recovery.
    """

    CONTAINMENT = "containment"
    EVIDENCE_PRESERVATION = "evidence_preservation"
    INVESTIGATION_FOLLOWUP = "investigation_followup"
    RECOVERY = "recovery"


class ResponseActionGroup(DukeModel):
    """A category of proposed response actions in a plan."""

    category: ResponseCategory
    actions: tuple[ResponseAction, ...]


class ResponsePlan(DukeModel):
    """A deterministic, dry-run-only proposal of response actions.

    ``incident`` is the plan's target. It is a *preliminary correlation
    record* created solely so that each :class:`ResponseAction` can
    carry the ``incident_id`` its model requires; it does not assert a
    confirmed compromise or exfiltration and is not a final incident
    report.
    """

    incident: Incident
    finding: Finding
    groups: tuple[ResponseActionGroup, ...] = Field(
        description=(
            "Proposed actions grouped by category, in response order: "
            "containment, evidence preservation, investigation follow-up, "
            "recovery."
        ),
    )

    def actions(self) -> tuple[ResponseAction, ...]:
        """Return every proposed action flattened across the groups."""
        return tuple(action for group in self.groups for action in group.actions)

    def entity_ids(self) -> tuple[UUID, ...]:
        """Return the distinct target entity IDs of the proposed actions."""
        return tuple(
            sorted(
                {
                    action.target_entity_id
                    for action in self.actions()
                    if action.target_entity_id is not None
                },
                key=str,
            )
        )
