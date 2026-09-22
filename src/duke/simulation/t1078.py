"""Safe, deterministic simulation of ATT&CK T1078 Valid Accounts."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5

from duke.core import Entity, EntityType, EventOutcome, SecurityEvent
from duke.scenarios import load_builtin_scenario
from duke.simulation.result import SimulationResult

_ID_NAMESPACE = UUID("10780000-0000-4000-8000-000000000000")
_DEFAULT_START = datetime(2026, 9, 22, 9, 0, tzinfo=UTC)


def _stable_id(value: str) -> UUID:
    """Create a repeatable identifier for synthetic scenario data."""
    return uuid5(_ID_NAMESPACE, value)


def _entity(
    entity_type: EntityType,
    identifier: str,
    display_name: str,
    **attributes: str,
) -> Entity:
    """Build a deterministic synthetic entity."""
    return Entity(
        id=_stable_id(f"entity:{identifier}"),
        entity_type=entity_type,
        identifier=identifier,
        display_name=display_name,
        attributes=attributes,
    )


def _event(
    sequence: int,
    occurred_at: datetime,
    action: str,
    source: str,
    actor: Entity,
    targets: list[Entity],
    **attributes: str,
) -> SecurityEvent:
    """Build a deterministic normalized security event."""
    return SecurityEvent(
        id=_stable_id(f"event:{sequence}:{action}"),
        occurred_at=occurred_at,
        action=action,
        outcome=EventOutcome.SUCCESS,
        source=source,
        actor_entity_id=actor.id,
        target_entity_ids=[target.id for target in targets],
        attributes=attributes,
    )


def generate_t1078_simulation(
    start_at: datetime = _DEFAULT_START,
) -> SimulationResult:
    """Generate a safe T1078 identity-compromise event sequence."""
    if start_at.tzinfo is None or start_at.utcoffset() is None:
        raise ValueError("start_at must be timezone-aware")

    user = _entity(
        EntityType.ACCOUNT,
        "alex.morgan@example.lab",
        "Alex Morgan",
        account_type="human",
        department="engineering",
        privilege_level="standard",
    )
    known_device = _entity(
        EntityType.HOST,
        "workstation-017",
        "Known Engineering Workstation",
        managed="true",
        device_trust="compliant",
    )
    unfamiliar_device = _entity(
        EntityType.HOST,
        "device-unknown-442",
        "Unfamiliar Device",
        managed="false",
        device_trust="unknown",
    )
    repository = _entity(
        EntityType.APPLICATION,
        "source-repository",
        "Source Repository",
        resource_type="code_repository",
        sensitivity="internal",
    )
    sensitive_file = _entity(
        EntityType.FILE,
        "repository/secrets/deployment-notes.txt",
        "Deployment Notes",
        classification="restricted",
    )
    privileged_service = _entity(
        EntityType.APPLICATION,
        "privileged-access-service",
        "Privileged Access Service",
        resource_type="identity_service",
    )
    archive = _entity(
        EntityType.FILE,
        "workspace/export-20260922.zip",
        "Synthetic Export Archive",
        file_type="archive",
        synthetic="true",
    )
    external_destination = _entity(
        EntityType.NETWORK_CONNECTION,
        "203.0.113.80:443",
        "Documentation Test Destination",
        address_class="documentation",
        protocol="https",
    )

    entities = (
        user,
        known_device,
        unfamiliar_device,
        repository,
        sensitive_file,
        privileged_service,
        archive,
        external_destination,
    )

    events = (
        _event(
            1,
            start_at,
            "authenticate",
            "identity_provider",
            user,
            [known_device],
            source_ip="192.0.2.10",
            network_context="known",
            device_context="known",
            mfa_result="satisfied",
        ),
        _event(
            2,
            start_at + timedelta(minutes=5),
            "access_application",
            "application",
            user,
            [repository],
            access_type="routine",
            session_device="workstation-017",
        ),
        _event(
            3,
            start_at + timedelta(hours=8),
            "authenticate",
            "identity_provider",
            user,
            [unfamiliar_device],
            source_ip="198.51.100.24",
            network_context="new",
            device_context="unfamiliar",
            mfa_result="not_present",
        ),
        _event(
            4,
            start_at + timedelta(hours=8, minutes=2),
            "enumerate_repository",
            "application",
            user,
            [repository],
            enumeration_scope="all_projects",
            session_device="device-unknown-442",
        ),
        _event(
            5,
            start_at + timedelta(hours=8, minutes=4),
            "read_file",
            "application",
            user,
            [sensitive_file],
            data_classification="restricted",
            session_device="device-unknown-442",
        ),
        _event(
            6,
            start_at + timedelta(hours=8, minutes=6),
            "request_privileged_access",
            "identity_provider",
            user,
            [privileged_service],
            requested_role="repository_administrator",
            approval_context="not_recorded",
        ),
        _event(
            7,
            start_at + timedelta(hours=8, minutes=9),
            "create_archive",
            "endpoint",
            user,
            [archive],
            source_item_count="14",
            session_device="device-unknown-442",
        ),
        _event(
            8,
            start_at + timedelta(hours=8, minutes=12),
            "network_connect",
            "network",
            user,
            [external_destination],
            bytes_sent="5242880",
            session_device="device-unknown-442",
        ),
    )

    return SimulationResult(
        scenario=load_builtin_scenario("t1078_valid_accounts"),
        entities=entities,
        events=events,
    )
