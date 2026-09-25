"""Safe, deterministic simulation of ATT&CK T1110.003 Password Spraying.

This simulation reproduces only the *defensive, observable* telemetry of a
password-spraying attempt: a burst of failed authentication events against
several distinct accounts from a single external source, followed by a single
successful authentication against one of those accounts. It does not perform
or imply any real authentication, does not store or generate any password or
credential value, and never labels an account as compromised or an actor as an
attacker.

The behavioural pattern intentionally mirrors its T1078 counterpart while
covering the complementary observable: T1078 models a valid-account compromise
with no failed logins, whereas this scenario models repeated failed
authentications followed by one later success.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5

from duke.core import Entity, EntityType, EventOutcome, SecurityEvent
from duke.scenarios import load_builtin_scenario
from duke.simulation.result import SimulationResult

_ID_NAMESPACE = UUID("11100000-0000-4000-8000-000000000000")
_DEFAULT_START = datetime(2026, 9, 25, 9, 0, tzinfo=UTC)

# Exact, documented timing offsets (all relative to ``start_at``):
# - the benign baseline authenticates at the fixed start time (offset 0h);
# - spraying begins later, 12h after the baseline;
# - the six failed attempts are evenly spaced 2 minutes apart;
# - the later successful authentication follows the failure sequence, 12
#   minutes after spraying begins.
_SPRAY_BEGIN = timedelta(hours=12)
_SPRAY_SPACING = timedelta(minutes=2)
_SPRAY_SUCCESS = timedelta(hours=12, minutes=12)

# A single external source doing the spraying. 198.51.100.0/24 is an RFC 5737
# documentation range, so it is never a real address.
_SPRAY_SOURCE_IP = "198.51.100.77"
# A documentation-safe IP for the benign internal baseline.
_BASELINE_SOURCE_IP = "203.0.113.10"

# Six distinct accounts targeted by the spray. No password or credential
# material ever appears; only the observed authentication outcome is modelled.
_TARGET_ACCOUNTS: tuple[tuple[str, str], ...] = (
    ("svc.integration", "Integration Service Account"),
    ("svc.reports", "Reporting Service Account"),
    ("svc.analytics", "Analytics Service Account"),
    ("svc.etl", "ETL Service Account"),
    ("d.garcia", "Dana Garcia"),
    ("a.okafor", "Amara Okafor"),
)

# The account whose authentication eventually succeeds (a prior spray target).
_SUCCESS_ACCOUNT = "svc.reports"


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
    outcome: EventOutcome,
    action: str,
    source: str,
    actor: Entity,
    targets: list[Entity],
    **attributes: str,
) -> SecurityEvent:
    """Build a deterministic normalized security event."""
    return SecurityEvent(
        id=_stable_id(f"event:{sequence}:{action}:{outcome.value}"),
        occurred_at=occurred_at,
        action=action,
        outcome=outcome,
        source=source,
        actor_entity_id=actor.id,
        target_entity_ids=[target.id for target in targets],
        attributes=attributes,
    )


def generate_t1110_simulation(
    start_at: datetime = _DEFAULT_START,
) -> SimulationResult:
    """Generate a safe T1110.003 password-spraying observable sequence."""
    if start_at.tzinfo is None or start_at.utcoffset() is None:
        raise ValueError("start_at must be timezone-aware")

    user_morales = _entity(
        EntityType.ACCOUNT,
        "r.morales",
        "R. Morales",
        account_type="human",
        department="sales",
        privilege_level="standard",
    )
    known_host = _entity(
        EntityType.HOST,
        "workstation-008",
        "Known Workstation",
        managed="true",
        zone="internal",
    )
    spray_source = _entity(
        EntityType.HOST,
        f"host-{_SPRAY_SOURCE_IP}",
        "External Source Host",
        managed="false",
        zone="internet",
    )
    portal = _entity(
        EntityType.APPLICATION,
        "web-portal",
        "Web Portal",
        resource_type="identity_service",
        exposure="internet_facing",
    )

    accounts = [
        _entity(
            EntityType.ACCOUNT,
            identifier,
            display_name,
            account_type="service" if identifier.startswith("svc.") else "human",
            privilege_level="standard",
        )
        for identifier, display_name in _TARGET_ACCOUNTS
    ]
    accounts_by_identifier = {entity.identifier: entity for entity in accounts}

    entities = (
        user_morales,
        known_host,
        spray_source,
        portal,
        *accounts,
    )

    # The benign baseline: a known user authenticates successfully from a
    # known, managed device at the fixed start time. Nothing about this record
    # is suspicious on its own; it exists to contrast with the later spray.
    baseline = _event(
        1,
        start_at,
        EventOutcome.SUCCESS,
        "authenticate",
        "identity_provider",
        user_morales,
        [known_host],
        source_ip=_BASELINE_SOURCE_IP,
        network_context="known",
        device_context="known",
        mfa_result="satisfied",
    )

    # The password-spraying burst: one failed authentication per distinct
    # target account, evenly spaced, all from the single external source.
    spray_events = []
    for index, account in enumerate(accounts):
        spray_events.append(
            _event(
                index + 2,
                start_at + _SPRAY_BEGIN + index * _SPRAY_SPACING,
                EventOutcome.FAILURE,
                "authenticate",
                "identity_provider",
                spray_source,
                [portal, account],
                source_ip=_SPRAY_SOURCE_IP,
                failure_reason="invalid_credentials",
                network_context="new",
                device_context="unknown",
                service="web-portal",
            )
        )

    # The later outcome: the spray's attempts stop, then one previously
    # targeted account authenticates successfully from the same source.
    # This record confirms only that an authentication succeeded; it asserts
    # nothing about compromise, actor identity, or impact.
    success_account = accounts_by_identifier[_SUCCESS_ACCOUNT]
    later_success = _event(
        len(accounts) + 2,
        start_at + _SPRAY_SUCCESS,
        EventOutcome.SUCCESS,
        "authenticate",
        "identity_provider",
        spray_source,
        [portal, success_account],
        source_ip=_SPRAY_SOURCE_IP,
        network_context="new",
        device_context="unknown",
        service="web-portal",
    )

    events = (baseline, *spray_events, later_success)

    return SimulationResult(
        scenario=load_builtin_scenario("t1110_brute_force"),
        entities=entities,
        events=events,
    )
