"""Incident: correlated findings tracked through the response lifecycle."""

from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field

from duke.core._base import DukeModel
from duke.core.enums import IncidentStatus, Severity


class Incident(DukeModel):
    """A correlated set of findings tracked as a single security incident.

    An incident always correlates at least one finding and affects at
    least one entity; without either, there is nothing to
    investigate or respond to. Supporting evidence is referenced
    directly, in addition to what each finding already references, so
    an incident can accumulate evidence discovered during
    investigation that is not tied to a single finding.
    """

    id: UUID = Field(default_factory=uuid4)
    opened_at: AwareDatetime = Field(description="When this incident was opened.")
    updated_at: AwareDatetime = Field(description="When this incident was updated.")
    closed_at: AwareDatetime | None = Field(
        default=None,
        description="When this incident was closed, if it has been.",
    )
    title: str
    summary: str
    status: IncidentStatus
    severity: Severity
    finding_ids: list[UUID] = Field(
        min_length=1,
        description="Identifiers of Finding objects correlated into this incident.",
    )
    evidence_ids: list[UUID] = Field(
        default_factory=list,
        description="Identifiers of Evidence objects gathered for this incident.",
    )
    affected_entity_ids: list[UUID] = Field(
        min_length=1,
        description="Identifiers of Entity objects affected by this incident.",
    )
