"""Safe, deterministic simulation of ATT&CK T1566.002 Spearphishing Link.

This simulation reproduces only the *defensive, observable* telemetry of a
spearphishing-link attempt: a synthetic email is delivered to a synthetic
employee, the employee opens the message and clicks its link, an inert
redirect record is produced, correlated DNS-style telemetry is observed, and
a defensive web filter blocks the reserved destination. It never delivers or
opens a real email, never clicks a real link, never resolves a domain or
makes a network request, never carries a payload, attachment, or macro, and
never collects or stores credentials.

A click record (``url_click``) asserts only that the synthetic UI action was
observed, never that the destination was reached. The redirect record
(``url_redirect``) asserts only that an inert telemetry record was produced
(``destination_reached=false``), not that any real redirect occurred. The DNS
observation (``dns_query``) stays inconclusive and unresolved, so it never
implies real resolution or a completed connection. The defensive block
(``url_blocked``) is a policy decision taken by the web filter, with
``established=false`` and ``network_effect=none`` — no connection completed.

The behaviour pattern mirrors the Repository's other scenarios in style while
covering the Initial Access / social-engineering entry vector that T1078 and
T1110 do not. It uses only RFC 2606 reserved domains (``example.invalid``) and
synthetic identities; no compromise, credential theft, impact, or successful
intrusion is ever asserted, on its own or in combination.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5

from duke.core import Entity, EntityType, EventOutcome, SecurityEvent
from duke.scenarios import load_builtin_scenario
from duke.simulation.result import SimulationResult

_ID_NAMESPACE = UUID("15660000-0000-4000-8000-000000000000")
_DEFAULT_START = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)

# Exact, documented timing offsets (all relative to ``start_at``):
# - delivery at the fixed start time (offset 0h);
# - the employee opens the message 2 minutes later;
# - the link click follows 4 minutes after start;
# - the inert redirect record 6 minutes after start;
# - the inconclusive DNS observation 8 minutes after start;
# - the defensive web-filter block 30 seconds after the DNS observation.
_OPEN_OFFSET = timedelta(minutes=2)
_CLICK_OFFSET = timedelta(minutes=4)
_REDIRECT_OFFSET = timedelta(minutes=6)
_DNS_OFFSET = timedelta(minutes=8)
_BLOCK_OFFSET = timedelta(minutes=8, seconds=30)

# The RFC 2606 reserved ``.invalid`` TLD is canonically inert: it is defined
# for documentation and testing and must never be used in a real network.
_RESERVED_DOMAIN = "example.invalid"
# A documentation-safe sender address on the same reserved domain. The sender
# is synthetic; no real person or mailbox exists behind it.
_SENDER = "noreply@example.invalid"
_RECIPIENT = "jamie.rendell@example.invalid"


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
        id=_stable_id(f"event:{sequence}:{action}"),
        occurred_at=occurred_at,
        action=action,
        outcome=outcome,
        source=source,
        actor_entity_id=actor.id,
        target_entity_ids=[target.id for target in targets],
        attributes=attributes,
    )


def generate_t1566_simulation(
    start_at: datetime = _DEFAULT_START,
) -> SimulationResult:
    """Generate a safe T1566.002 spearphishing-link observable sequence."""
    if start_at.tzinfo is None or start_at.utcoffset() is None:
        raise ValueError("start_at must be timezone-aware")

    employee = _entity(
        EntityType.USER,
        _RECIPIENT,
        "Jamie Rendell",
        department="finance",
        role="analyst",
        training_status="active",
    )
    mail_gateway = _entity(
        EntityType.APPLICATION,
        "mail-gateway",
        "Mail Gateway",
        service="email_gateway",
        exposure="internal",
    )
    message = _entity(
        EntityType.FILE,
        "message/msg-001.html",
        "Spearphishing Message",
        medium="email",
        synthetic="true",
        link_domain=_RESERVED_DOMAIN,
        link_inert="true",
    )
    workstation = _entity(
        EntityType.HOST,
        "workstation-022",
        "Workstation",
        managed="true",
        zone="internal",
    )
    reserved_destination = _entity(
        EntityType.NETWORK_CONNECTION,
        f"{_RESERVED_DOMAIN}:443",
        "Reserved Domain Destination",
        address_class="reserved",
        domain=_RESERVED_DOMAIN,
        protocol="https",
    )

    entities = (
        employee,
        mail_gateway,
        message,
        workstation,
        reserved_destination,
    )

    events = (
        _event(
            1,
            start_at,
            EventOutcome.SUCCESS,
            "email_receive",
            "email_gateway",
            mail_gateway,
            [message, employee],
            sender=_SENDER,
            recipient=_RECIPIENT,
            classification="untrusted",
            message_id="msg-001",
        ),
        _event(
            2,
            start_at + _OPEN_OFFSET,
            EventOutcome.SUCCESS,
            "email_open",
            "email_client",
            employee,
            [message, workstation],
            client="mail_client",
            device_context="managed",
            link_domain=_RESERVED_DOMAIN,
        ),
        _event(
            3,
            start_at + _CLICK_OFFSET,
            EventOutcome.SUCCESS,
            "url_click",
            "endpoint",
            employee,
            [reserved_destination],
            click_context="email_client",
            destination_domain=_RESERVED_DOMAIN,
            session_device="workstation-022",
        ),
        _event(
            4,
            start_at + _REDIRECT_OFFSET,
            EventOutcome.SUCCESS,
            "url_redirect",
            "proxy",
            employee,
            [reserved_destination],
            redirect_inert="true",
            destination_domain=_RESERVED_DOMAIN,
            destination_reached="false",
        ),
        _event(
            5,
            start_at + _DNS_OFFSET,
            EventOutcome.UNKNOWN,
            "dns_query",
            "dns_resolver",
            employee,
            [reserved_destination],
            query_type="A",
            destination_domain=_RESERVED_DOMAIN,
            resolved="false",
            resolution_inconclusive="true",
            address_class="reserved",
        ),
        _event(
            6,
            start_at + _BLOCK_OFFSET,
            EventOutcome.SUCCESS,
            "url_blocked",
            "web_filter",
            workstation,
            [reserved_destination],
            decision="blocked",
            control="web_filter",
            established="false",
            network_effect="none",
            defensive_control="true",
        ),
    )

    return SimulationResult(
        scenario=load_builtin_scenario("t1566_phishing"),
        entities=entities,
        events=events,
    )
