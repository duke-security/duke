"""Finding: a detection result derived from events and evidence."""

from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field

from duke.core._base import DukeModel
from duke.core.enums import FindingStatus, Severity


class Finding(DukeModel):
    """A single detection result.

    A ``Finding`` records that some detection logic fired, why it
    fired (``detection_name`` and ``detection_details``), and points
    at the events, evidence, and entities that support it by
    identifier, rather than embedding them, since the same event or
    piece of evidence can support multiple findings.
    """

    id: UUID = Field(default_factory=uuid4)
    created_at: AwareDatetime = Field(description="When this finding was generated.")
    title: str
    description: str
    detection_name: str = Field(
        description="Name of the detection rule or logic that produced this finding.",
    )
    detection_details: str = Field(
        description="Explanation of why the detection logic fired for this finding.",
    )
    technique_id: str | None = Field(
        default=None,
        description="Associated MITRE ATT&CK technique identifier, e.g. 'T1078'.",
    )
    severity: Severity
    status: FindingStatus
    event_ids: list[UUID] = Field(
        default_factory=list,
        description="Identifiers of SecurityEvent objects supporting this finding.",
    )
    evidence_ids: list[UUID] = Field(
        default_factory=list,
        description="Identifiers of Evidence objects supporting this finding.",
    )
    entity_ids: list[UUID] = Field(
        default_factory=list,
        description="Identifiers of Entity objects implicated by this finding.",
    )
    confidence: int = Field(
        ge=0,
        le=100,
        description="Detection confidence expressed as an integer from 0 to 100.",
    )
