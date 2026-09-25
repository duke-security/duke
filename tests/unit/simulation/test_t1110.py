"""Tests for the safe T1110.003 password-spraying simulation."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from duke.core import EntityType, EventOutcome
from duke.simulation import generate_t1110_simulation

# Exact documented timing offsets (mirrors the implementation constants):
# baseline at start, spraying begins 12h later, failures every 2 minutes, and
# the later success 12 minutes after spraying begins.
_SPRAY_BEGIN = timedelta(hours=12)
_SPRAY_SPACING = timedelta(minutes=2)
_SPRAY_SUCCESS = timedelta(hours=12, minutes=12)


def test_generates_expected_event_sequence() -> None:
    result = generate_t1110_simulation()

    assert len(result.entities) == 10
    assert len(result.events) == 8
    # 1 benign baseline + 6 single failures + 1 later success.
    assert [
        (event.action, event.outcome) for event in result.events
    ] == [
        ("authenticate", EventOutcome.SUCCESS),
        ("authenticate", EventOutcome.FAILURE),
        ("authenticate", EventOutcome.FAILURE),
        ("authenticate", EventOutcome.FAILURE),
        ("authenticate", EventOutcome.FAILURE),
        ("authenticate", EventOutcome.FAILURE),
        ("authenticate", EventOutcome.FAILURE),
        ("authenticate", EventOutcome.SUCCESS),
    ]


def test_simulation_is_deterministic() -> None:
    first = generate_t1110_simulation()
    second = generate_t1110_simulation()

    assert first == second


def test_events_are_chronological() -> None:
    result = generate_t1110_simulation()
    timestamps = [event.occurred_at for event in result.events]

    assert timestamps == sorted(timestamps)


def test_exact_documented_timing_offsets() -> None:
    """The benign baseline starts at the fixed time, failures are evenly
    spaced, and the later success follows the failure sequence."""
    start = datetime(2026, 9, 25, 9, 0, tzinfo=UTC)
    result = generate_t1110_simulation(start)

    assert result.events[0].occurred_at == start  # benign baseline at start
    # Six failures, evenly spaced 2 minutes apart, beginning 12h after start.
    for index in range(1, 7):
        assert result.events[index].occurred_at == (
            start + _SPRAY_BEGIN + (index - 1) * _SPRAY_SPACING
        )
    # The later success follows the failure sequence.
    assert result.events[7].occurred_at == start + _SPRAY_SUCCESS


def test_one_failed_authentication_per_distinct_target_account() -> None:
    result = generate_t1110_simulation()

    failures = [
        event for event in result.events
        if event.outcome is EventOutcome.FAILURE
    ]
    assert len(failures) == 6
    # Every failure targets a distinct account.
    failure_targets = set()
    for event in failures:
        account_ids = {
            target for target in event.target_entity_ids
            if result.entity_by_identifier(
                next(
                    e.identifier for e in result.entities if e.id == target
                )
            ).entity_type is EntityType.ACCOUNT
        }
        assert len(account_ids) == 1
        failure_targets.update(account_ids)
    assert len(failure_targets) == 6


def test_later_success_targets_a_previously_sprayed_account() -> None:
    result = generate_t1110_simulation()

    failures = [
        event for event in result.events
        if event.outcome is EventOutcome.FAILURE
    ]
    sprayed_accounts = set()
    for event in failures:
        for target in event.target_entity_ids:
            entity = next(e for e in result.entities if e.id == target)
            if entity.entity_type is EntityType.ACCOUNT:
                sprayed_accounts.add(entity.id)

    success = result.events[-1]
    assert success.outcome is EventOutcome.SUCCESS
    success_account_ids = {
        target for target in success.target_entity_ids
        if next(e for e in result.entities if e.id == target).entity_type
        is EntityType.ACCOUNT
    }
    assert len(success_account_ids) == 1
    assert success_account_ids <= sprayed_accounts


def test_benign_baseline_precedes_spraying() -> None:
    result = generate_t1110_simulation()

    baseline = result.events[0]
    assert baseline.outcome is EventOutcome.SUCCESS
    assert baseline.occurred_at == result.events[1].occurred_at - _SPRAY_BEGIN
    assert baseline.attributes.get("network_context") == "known"
    assert baseline.attributes.get("device_context") == "known"


def test_event_relationships_reference_known_entities() -> None:
    result = generate_t1110_simulation()
    entity_ids = {entity.id for entity in result.entities}

    for event in result.events:
        assert isinstance(event.actor_entity_id, UUID)
        assert event.actor_entity_id in entity_ids
        assert set(event.target_entity_ids) <= entity_ids


def test_events_do_not_contain_answer_labels() -> None:
    result = generate_t1110_simulation()
    prohibited_keys = {
        "attack",
        "compromised",
        "malicious",
        "suspicious",
        "threat",
    }

    for event in result.events:
        assert prohibited_keys.isdisjoint(event.attributes)


def test_no_credential_or_secret_material_in_any_attribute() -> None:
    """Neither entities nor events carry secret material.

    The permitted normalized failure label ``invalid_credentials`` is the
    only credential-related token allowed, and it is validated separately.
    Every other occurrence of ``password``, ``credential``, ``secret``,
    ``token``, or ``passwd`` — as a key fragment or as a standalone value
    word — is rejected.
    """
    result = generate_t1110_simulation()
    forbidden_key_fragments = ("password", "passwd", "secret", "token", "credential")
    forbidden_value_words = {"password", "passwd", "secret", "token", "credential"}
    allowed_label = "invalid_credentials"

    for entity in result.entities:
        for key, value in entity.attributes.items():
            normalized_key = key.lower()
            assert not any(
                fragment in normalized_key
                for fragment in forbidden_key_fragments
            ), f"entity {entity.identifier} uses secret-named key {key!r}"
            tokens = set(value.lower().split())
            # Carve out exactly the permitted telemetry label, then require no
            # forbidden credential word remains in the value.
            tokens.discard(allowed_label)
            assert forbidden_value_words.isdisjoint(tokens), (
                f"entity {entity.identifier} attr {key!r} carries "
                f"credential material: {value!r}"
            )
    for event in result.events:
        for key, value in event.attributes.items():
            normalized_key = key.lower()
            assert not any(
                fragment in normalized_key
                for fragment in forbidden_key_fragments
            ), f"event {event.id} uses secret-named key {key!r}"
            tokens = set(value.lower().split())
            tokens.discard(allowed_label)
            assert forbidden_value_words.isdisjoint(tokens), (
                f"event {event.id} attr {key!r} carries credential material: "
                f"{value!r}"
            )


def test_failure_reason_is_an_observable_label_only() -> None:
    """The failure reason describes the observed outcome without a value."""
    result = generate_t1110_simulation()

    for event in result.events:
        if event.outcome is EventOutcome.FAILURE:
            assert event.attributes.get("failure_reason") == "invalid_credentials"


def test_all_ip_addresses_use_documentation_ranges() -> None:
    """Every IP in scope is in an RFC 5737 documentation range."""
    result = generate_t1110_simulation()
    documentation_prefixes = ("192.0.2.", "198.51.100.", "203.0.113.")

    for event in result.events:
        source_ip = event.attributes.get("source_ip")
        if source_ip is None:
            continue
        assert any(
            source_ip.startswith(prefix) for prefix in documentation_prefixes
        ), f"non-documentation IP in event: {source_ip}"


def test_generation_performs_no_side_effecting_activity(
    tmp_path, monkeypatch
) -> None:
    """Generation must not open sockets, spawn subprocesses, authenticate, or
    touch the filesystem."""
    import socket
    import subprocess

    def _raise(*_args, **_kwargs):
        raise AssertionError("generation performed side-effecting activity")

    monkeypatch.setattr(socket, "socket", _raise)
    monkeypatch.setattr(subprocess, "Popen", _raise)
    monkeypatch.setattr(subprocess, "run", _raise)

    # Run from a clean temporary directory and require no files to be created.
    monkeypatch.chdir(tmp_path)
    before = {p for p in tmp_path.rglob("*")}

    result = generate_t1110_simulation()

    after = {p for p in tmp_path.rglob("*")}
    assert before == after
    # Sanity: the result is pure in-memory data.
    assert len(result.entities) == 10
    assert len(result.events) == 8


def test_later_success_takes_cautious_analytic_language() -> None:
    """The later success confirms only that an authentication succeeded. It
    must not assert compromise, attacker ownership, maliciousness, or effect."""
    result = generate_t1110_simulation()
    success = result.events[-1]

    assert success.outcome is EventOutcome.SUCCESS
    assert success.action == "authenticate"
    # Attributes describe observed context, never analytic conclusions.
    assert success.attributes.get("network_context") == "new"
    assert success.attributes.get("device_context") == "unknown"
    for key in success.attributes:
        assert key in {
            "source_ip",
            "network_context",
            "device_context",
            "service",
        }
    prohibited_values = {
        "compromised",
        "attacker",
        "malicious",
        "breach",
        "exfiltrat",
        "exploited",
    }
    joined = " ".join(success.attributes.values()).lower()
    assert prohibited_values.isdisjoint(joined.split())


def test_naive_start_time_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        generate_t1110_simulation(datetime(2026, 9, 25, 9, 0))


def test_entity_lookup_uses_natural_identifier() -> None:
    result = generate_t1110_simulation()

    entity = result.entity_by_identifier("r.morales")

    assert entity.display_name == "R. Morales"


def test_unknown_entity_lookup_is_rejected() -> None:
    result = generate_t1110_simulation()

    with pytest.raises(LookupError, match="Entity not found"):
        result.entity_by_identifier("missing@example.lab")
