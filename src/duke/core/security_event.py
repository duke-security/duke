"""SecurityEvent: normalized, vendor-neutral observable activity."""

from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field

from duke.core._base import DukeModel
from duke.core.enums import EventOutcome


class SecurityEvent(DukeModel):
    """A single normalized observation of activity.

    A ``SecurityEvent`` represents *what was observed*, independent of
    any cloud provider, operating system, SIEM, or EDR. Provider- or
    platform-specific telemetry (a CloudTrail record, a Windows event
    log, an EDR alert, ...) must be translated into this shape by an
    adapter before it enters Duke's core.
    """

    id: UUID = Field(default_factory=uuid4)
    occurred_at: AwareDatetime = Field(
        description="When the observed activity occurred (timezone-aware).",
    )
    action: str = Field(
        description=(
            "Normalized verb describing what happened, e.g. 'authenticate', "
            "'process_create', or 'network_connect'."
        ),
    )
    outcome: EventOutcome
    source: str = Field(
        description=(
            "Normalized category of the telemetry's origin, e.g. "
            "'identity_provider', 'endpoint', or 'network'. Never a vendor name."
        ),
    )
    actor_entity_id: UUID | None = Field(
        default=None,
        description="Identifier of the Entity that performed the action, if known.",
    )
    target_entity_ids: list[UUID] = Field(
        default_factory=list,
        description="Identifiers of Entity objects affected by the action.",
    )
    attributes: dict[str, str] = Field(
        default_factory=dict,
        description="Additional normalized, vendor-neutral key-value attributes.",
    )
