"""Enumerations shared across Duke's core domain models.

Each enum exists to prevent inconsistent, free-text values for a
concept that has a small, well-known set of valid states.
"""

from enum import StrEnum


class EntityType(StrEnum):
    """The kind of actor or object a normalized :class:`Entity` represents."""

    USER = "user"
    ACCOUNT = "account"
    HOST = "host"
    PROCESS = "process"
    FILE = "file"
    NETWORK_CONNECTION = "network_connection"
    CLOUD_RESOURCE = "cloud_resource"
    APPLICATION = "application"


class Severity(StrEnum):
    """A normalized severity scale used by findings and incidents."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventOutcome(StrEnum):
    """Whether an observed action succeeded, failed, or is unknown."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class EvidenceRelationship(StrEnum):
    """How a piece of evidence relates to the assessment it informs."""

    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    PROVIDES_CONTEXT = "provides_context"


class FindingStatus(StrEnum):
    """The lifecycle state of a :class:`Finding`."""

    NEW = "new"
    UNDER_REVIEW = "under_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class IncidentStatus(StrEnum):
    """The lifecycle state of an :class:`Incident`."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class ResponseStatus(StrEnum):
    """The lifecycle state of a :class:`ResponseAction`."""

    PLANNED = "planned"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"


class ResponseRisk(StrEnum):
    """The risk level of taking a :class:`ResponseAction`."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
