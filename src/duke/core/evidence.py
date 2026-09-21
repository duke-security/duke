"""Evidence: a piece of support for or against an analytic assessment."""

from typing import Self
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, model_validator

from duke.core._base import DukeModel
from duke.core.enums import EvidenceRelationship


class Evidence(DukeModel):
    """A single piece of evidence used to reason about a finding or incident.

    Evidence always traces back to something concrete: either a
    :class:`~duke.core.security_event.SecurityEvent` (via
    ``source_event_id``) or a non-event artefact such as a file hash or
    log excerpt (via ``source_artifact_reference``). It also records
    its ``relationship`` to the assessment it informs, since evidence
    is not always corroborating.
    """

    id: UUID = Field(default_factory=uuid4)
    collected_at: AwareDatetime = Field(
        description="When this evidence was collected or recorded.",
    )
    description: str = Field(description="What this evidence shows and why it matters.")
    relationship: EvidenceRelationship = Field(
        description=(
            "Whether this evidence supports, contradicts, or provides "
            "context for an assessment."
        ),
    )
    source_event_id: UUID | None = Field(
        default=None,
        description="Identifier of the source SecurityEvent, if any.",
    )
    source_artifact_reference: str | None = Field(
        default=None,
        description=(
            "Identifier for a non-event artefact this evidence was derived "
            "from, e.g. a file hash or log excerpt reference."
        ),
    )

    @model_validator(mode="after")
    def _require_a_source(self) -> Self:
        if self.source_event_id is None and self.source_artifact_reference is None:
            raise ValueError(
                "Evidence must identify a source_event_id or "
                "a source_artifact_reference."
            )
        return self
