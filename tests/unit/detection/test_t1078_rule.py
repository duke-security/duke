"""Tests for the safe, deterministic T1078 detection rule."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5

from duke.core import (
    Entity,
    EntityType,
    EventOutcome,
    FindingStatus,
    SecurityEvent,
    Severity,
)
from duke.detection import detect_t1078
from duke.simulation import generate_t1078_simulation

_TEST_NS = UUID("d3ad0000-0000-4000-8000-000000000000")
BASE = datetime(2026, 9, 22, 9, 0, tzinfo=UTC)


def _entity(identifier: str) -> Entity:
    return Entity(
        id=uuid5(_TEST_NS, f"entity:{identifier}"),
        entity_type=EntityType.HOST,
        identifier=identifier,
        display_name=identifier,
    )


def _event(
    action: str,
    occurred_at: datetime,
    actor: Entity,
    targets: list[Entity] | None = None,
    **attributes: str,
) -> SecurityEvent:
    return SecurityEvent(
        id=uuid5(_TEST_NS, f"{action}:{occurred_at.isoformat()}"),
        occurred_at=occurred_at,
        action=action,
        outcome=EventOutcome.SUCCESS,
        source="identity_provider",
        actor_entity_id=actor.id,
        target_entity_ids=[target.id for target in (targets or [])],
        attributes=attributes,
    )


def _full_chain() -> tuple[Entity, tuple[SecurityEvent, ...]]:
    """A single actor with a baseline and a full compromise chain."""
    actor = _entity("alex")
    device = _entity("unknown-device")
    follow = [
        ("enumerate_repository", timedelta(minutes=2)),
        ("read_file", timedelta(minutes=4)),
        ("request_privileged_access", timedelta(minutes=6)),
        ("create_archive", timedelta(minutes=9)),
        ("network_connect", timedelta(minutes=12)),
    ]
    events = [
        _event(
            "authenticate",
            BASE,
            actor,
            [actor],
            network_context="known",
            device_context="known",
        ),
        _event(
            "authenticate",
            BASE + timedelta(hours=8),
            actor,
            [device],
            network_context="new",
            device_context="unfamiliar",
        ),
    ]
    for action, delta in follow:
        events.append(
            _event(
                action,
                BASE + timedelta(hours=8) + delta,
                actor,
                data_classification=(
                    "restricted" if action == "read_file" else "internal"
                ),
            )
        )
    return actor, tuple(events)


def test_true_positive_detects_compromise() -> None:
    result = generate_t1078_simulation()
    findings = detect_t1078(result.events)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.detection_name == "compromised-identity-sequence"
    assert finding.technique_id == "T1078"
    assert finding.confidence == 90
    assert finding.severity is Severity.HIGH
    assert finding.status is FindingStatus.NEW


def test_benign_activity_returns_no_findings() -> None:
    actor, chain = _full_chain()
    benign = (
        chain[0],  # known-good baseline
        _event("access_application", BASE + timedelta(minutes=5), actor),
    )
    assert detect_t1078(benign) == ()


def test_empty_input_returns_no_findings() -> None:
    assert detect_t1078(()) == ()


def test_new_context_login_alone_produces_no_finding() -> None:
    baseline, new_login = _full_chain()[1][0], _full_chain()[1][1]
    assert detect_t1078((baseline, new_login)) == ()


def test_new_context_without_baseline_produces_no_finding() -> None:
    # New-context activity is gated behind a known-good baseline.
    _actor, chain = _full_chain()
    new_login = chain[1]
    assert detect_t1078((new_login,)) == ()


def test_insufficient_score_produces_no_finding() -> None:
    actor, chain = _full_chain()
    baseline, new_login = chain[0], chain[1]
    # New context (25) + enumeration (10) + archive (10) = 45 < 60.
    low = (
        baseline,
        new_login,
        _event("enumerate_repository", BASE + timedelta(hours=8, minutes=2), actor),
        _event("create_archive", BASE + timedelta(hours=8, minutes=5), actor),
    )
    assert detect_t1078(low) == ()


def test_correlation_window_expiry_drops_follow_ons() -> None:
    actor, chain = _full_chain()
    baseline, new_login = chain[0], chain[1]
    late = (
        baseline,
        new_login,
        # Behaviours more than 15 minutes after the new-context login.
        _event(
            "read_file",
            BASE + timedelta(hours=8, minutes=20),
            actor,
            data_classification="restricted",
        ),
        _event("network_connect", BASE + timedelta(hours=8, minutes=25), actor),
    )
    assert detect_t1078(late) == ()


def test_wrong_actor_is_ignored() -> None:
    actor_b, chain_b = _full_chain()
    actor_a = _entity("benign")
    events = (
        *chain_b,
        _event(
            "authenticate",
            BASE,
            actor_a,
            network_context="known",
            device_context="known",
        ),
        _event("access_application", BASE + timedelta(minutes=5), actor_a),
    )

    findings = detect_t1078(events)

    assert len(findings) == 1
    assert actor_b.id in findings[0].entity_ids
    assert actor_a.id not in findings[0].entity_ids


def test_duplicate_behaviours_do_not_inflate_score() -> None:
    actor, chain = _full_chain()
    baseline, new_login = chain[0], chain[1]
    # Restricted (15) + privilege (15) = 30; new context 25 -> 55 < 60.
    # A second restricted read must NOT be double-counted (would reach 70).
    dup = (
        baseline,
        new_login,
        _event(
            "read_file",
            BASE + timedelta(hours=8, minutes=2),
            actor,
            data_classification="restricted",
        ),
        _event(
            "request_privileged_access",
            BASE + timedelta(hours=8, minutes=4),
            actor,
        ),
        _event(
            "read_file",
            BASE + timedelta(hours=8, minutes=6),
            actor,
            data_classification="restricted",
        ),
    )
    assert detect_t1078(dup) == ()


def test_deterministic_output_and_ids() -> None:
    result = generate_t1078_simulation()
    first = detect_t1078(result.events)
    second = detect_t1078(result.events)

    assert first == second
    assert first[0].id == second[0].id
    assert len({finding.id for finding in first}) == len(first)


def test_severity_derived_from_confidence() -> None:
    actor, chain = _full_chain()
    baseline, new_login = chain[0], chain[1]
    # New context (25) + restricted (15) + privilege (15) + enum (10) = 65.
    medium = (
        baseline,
        new_login,
        _event(
            "read_file",
            BASE + timedelta(hours=8, minutes=2),
            actor,
            data_classification="restricted",
        ),
        _event(
            "request_privileged_access",
            BASE + timedelta(hours=8, minutes=4),
            actor,
        ),
        _event("enumerate_repository", BASE + timedelta(hours=8, minutes=6), actor),
    )
    findings = detect_t1078(medium)
    assert len(findings) == 1
    assert findings[0].confidence == 65
    assert findings[0].severity is Severity.MEDIUM


def test_event_relationships_reference_supporting_events() -> None:
    result = generate_t1078_simulation()
    finding = detect_t1078(result.events)[0]
    event_ids = {event.id for event in result.events}

    assert set(finding.event_ids) <= event_ids
    # Baseline + new-context login + five follow-on behaviours.
    assert len(finding.event_ids) == 7
    assert finding.confidence <= 100


def test_entity_relationships_include_actor_and_implicated_entities() -> None:
    result = generate_t1078_simulation()
    finding = detect_t1078(result.events)[0]
    id_to_identifier = {entity.id: entity.identifier for entity in result.entities}
    implicated = {id_to_identifier[i] for i in finding.entity_ids}

    assert implicated == {
        "alex.morgan@example.lab",
        "device-unknown-442",
        "source-repository",
        "repository/secrets/deployment-notes.txt",
        "privileged-access-service",
        "workspace/export-20260922.zip",
        "203.0.113.80:443",
    }
    # The known-good baseline device stays contextual, not implicated.
    assert "workstation-017" not in implicated
