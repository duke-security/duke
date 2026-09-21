"""Duke's vendor-neutral core domain model.

Every model in this package is independent of any specific cloud
provider, SIEM, EDR, or operating system. Provider-specific data must
be translated into these models through an adapter; see
docs/decisions/0001-vendor-agnostic-core.md.
"""

from duke.core.entity import Entity
from duke.core.enums import (
    EntityType,
    EventOutcome,
    EvidenceRelationship,
    FindingStatus,
    IncidentStatus,
    ResponseRisk,
    ResponseStatus,
    Severity,
)
from duke.core.evidence import Evidence
from duke.core.finding import Finding
from duke.core.incident import Incident
from duke.core.response_action import ResponseAction
from duke.core.scenario import Scenario
from duke.core.security_event import SecurityEvent

__all__ = [
    "Entity",
    "EntityType",
    "Evidence",
    "EvidenceRelationship",
    "EventOutcome",
    "Finding",
    "FindingStatus",
    "Incident",
    "IncidentStatus",
    "ResponseAction",
    "ResponseRisk",
    "ResponseStatus",
    "Scenario",
    "SecurityEvent",
    "Severity",
]
