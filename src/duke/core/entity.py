"""Entity: a normalized actor or object observed in security telemetry."""

from uuid import UUID, uuid4

from pydantic import Field

from duke.core._base import DukeModel
from duke.core.enums import EntityType


class Entity(DukeModel):
    """A vendor-neutral actor or object, e.g. a user, host, or process.

    Other models reference entities by ``id`` rather than embedding
    them, since the same entity (a user or a host) is typically
    involved in many events, findings, and incidents.
    """

    id: UUID = Field(default_factory=uuid4)
    entity_type: EntityType
    identifier: str = Field(
        description=(
            "Stable natural identifier for the entity, e.g. a username, "
            "hostname, or IP address."
        ),
    )
    display_name: str | None = Field(
        default=None,
        description="Human-friendly name, if different from the identifier.",
    )
    attributes: dict[str, str] = Field(
        default_factory=dict,
        description="Additional normalized, vendor-neutral key-value attributes.",
    )
