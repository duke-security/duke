"""ResponseAction: a safe, auditable response taken against an incident."""

from typing import Self
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, model_validator

from duke.core._base import DukeModel
from duke.core.enums import ResponseRisk, ResponseStatus


class ResponseAction(DukeModel):
    """A single response action taken, or proposed, against an incident.

    Every response action records enough context to be reviewed and
    audited before it runs: why it is being taken (``purpose``), how
    risky it is, whether it needs approval, whether it is a dry run,
    how to verify it worked, and how to roll it back if it supports
    rollback.
    """

    id: UUID = Field(default_factory=uuid4)
    created_at: AwareDatetime = Field(description="When this action was proposed.")
    incident_id: UUID = Field(description="Identifier of the responded-to Incident.")
    target_entity_id: UUID | None = Field(
        default=None,
        description="Identifier of the Entity this action targets, if any.",
    )
    name: str
    purpose: str = Field(description="Why this action is being taken.")
    risk: ResponseRisk
    requires_approval: bool = Field(
        description="Whether a human must approve this action before it runs.",
    )
    dry_run: bool = Field(
        description="Whether this action only simulates its effect.",
    )
    status: ResponseStatus
    verification_guidance: str = Field(
        description="How to verify whether this action had its intended effect.",
    )
    supports_rollback: bool = Field(
        description="Whether this action's effect can be reversed.",
    )
    rollback_guidance: str | None = Field(
        default=None,
        description=(
            "How to reverse this action's effect. Required when "
            "supports_rollback is True."
        ),
    )

    @model_validator(mode="after")
    def _rollback_guidance_required_when_supported(self) -> Self:
        if self.supports_rollback and not self.rollback_guidance:
            raise ValueError(
                "rollback_guidance is required when supports_rollback is True."
            )
        return self
