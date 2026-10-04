"""Tests for the safe T1566.002 spearphishing-link simulation."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from duke.core import EntityType, EventOutcome
from duke.simulation import generate_t1566_simulation

# Exact documented timing offsets (mirrors the implementation constants):
# delivery at start, open +2m, click +4m, redirect +6m, dns +8m, block +8m30s.
_OPEN_OFFSET = timedelta(minutes=2)
_CLICK_OFFSET = timedelta(minutes=4)
_REDIRECT_OFFSET = timedelta(minutes=6)
_DNS_OFFSET = timedelta(minutes=8)
_BLOCK_OFFSET = timedelta(minutes=8, seconds=30)

_REQUIRED_ACTIONS = (
    "email_receive",
    "email_open",
    "url_click",
    "url_redirect",
    "dns_query",
    "url_blocked",
)


def test_generates_expected_event_sequence() -> None:
    result = generate_t1566_simulation()

    assert len(result.entities) == 5
    assert len(result.events) == 6
    assert [(event.action, event.outcome) for event in result.events] == [
        ("email_receive", EventOutcome.SUCCESS),
        ("email_open", EventOutcome.SUCCESS),
        ("url_click", EventOutcome.SUCCESS),
        ("url_redirect", EventOutcome.SUCCESS),
        ("dns_query", EventOutcome.UNKNOWN),
        ("url_blocked", EventOutcome.SUCCESS),
    ]


def test_event_actions_are_distinct() -> None:
    result = generate_t1566_simulation()

    actions = [event.action for event in result.events]
    assert actions == list(_REQUIRED_ACTIONS)
    assert len(set(actions)) == len(actions)


def test_simulation_is_deterministic() -> None:
    first = generate_t1566_simulation()
    second = generate_t1566_simulation()

    assert first == second


def test_events_are_chronological() -> None:
    result = generate_t1566_simulation()
    timestamps = [event.occurred_at for event in result.events]

    assert timestamps == sorted(timestamps)


def test_exact_documented_timing_offsets() -> None:
    start = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
    result = generate_t1566_simulation(start)

    assert result.events[0].occurred_at == start  # delivery at start
    assert result.events[1].occurred_at == start + _OPEN_OFFSET
    assert result.events[2].occurred_at == start + _CLICK_OFFSET
    assert result.events[3].occurred_at == start + _REDIRECT_OFFSET
    assert result.events[4].occurred_at == start + _DNS_OFFSET
    assert result.events[5].occurred_at == start + _BLOCK_OFFSET


def test_entity_lookup_uses_natural_identifier() -> None:
    result = generate_t1566_simulation()

    employee = result.entity_by_identifier("jamie.rendell@example.invalid")

    assert employee.display_name == "Jamie Rendell"


def test_unknown_entity_lookup_is_rejected() -> None:
    result = generate_t1566_simulation()

    with pytest.raises(LookupError, match="Entity not found"):
        result.entity_by_identifier("missing@example.invalid")


def test_entity_types_cover_the_five_catalogued_entities() -> None:
    result = generate_t1566_simulation()

    by_identifier = {entity.identifier: entity for entity in result.entities}
    assert by_identifier["jamie.rendell@example.invalid"].entity_type is EntityType.USER
    assert by_identifier["mail-gateway"].entity_type is EntityType.APPLICATION
    assert by_identifier["message/msg-001.html"].entity_type is EntityType.FILE
    assert by_identifier["workstation-022"].entity_type is EntityType.HOST
    assert by_identifier["example.invalid:443"].entity_type is (
        EntityType.NETWORK_CONNECTION
    )


def test_event_relationships_reference_known_entities() -> None:
    result = generate_t1566_simulation()
    entity_ids = {entity.id for entity in result.entities}

    for event in result.events:
        assert isinstance(event.actor_entity_id, UUID)
        assert event.actor_entity_id in entity_ids
        assert set(event.target_entity_ids) <= entity_ids


def test_events_do_not_contain_answer_labels() -> None:
    result = generate_t1566_simulation()
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
    result = generate_t1566_simulation()
    forbidden_key_fragments = ("password", "passwd", "secret", "token", "credential")
    forbidden_value_words = {"password", "passwd", "secret", "token", "credential"}

    for entity in result.entities:
        for key, value in entity.attributes.items():
            normalized_key = key.lower()
            assert not any(
                fragment in normalized_key for fragment in forbidden_key_fragments
            ), f"entity {entity.identifier} uses secret-named key {key!r}"
            tokens = set(value.lower().split())
            assert forbidden_value_words.isdisjoint(tokens), (
                f"entity {entity.identifier} attr {key!r} carries "
                f"credential material: {value!r}"
            )
    for event in result.events:
        for key, value in event.attributes.items():
            normalized_key = key.lower()
            assert not any(
                fragment in normalized_key for fragment in forbidden_key_fragments
            ), f"event {event.id} uses secret-named key {key!r}"
            tokens = set(value.lower().split())
            assert forbidden_value_words.isdisjoint(tokens), (
                f"event {event.id} attr {key!r} carries credential material: {value!r}"
            )


def test_all_attribute_values_are_strings() -> None:
    """Every entity and event attribute value matches the model's dict[str, str]."""
    result = generate_t1566_simulation()

    for entity in result.entities:
        for key, value in entity.attributes.items():
            assert isinstance(key, str), f"entity {entity.identifier} key {key!r}"
            assert isinstance(value, str), (
                f"entity {entity.identifier} attr {key!r} is {type(value).__name__}"
            )
    for event in result.events:
        for key, value in event.attributes.items():
            assert isinstance(key, str), f"event {event.id} key {key!r}"
            assert isinstance(value, str), (
                f"event {event.id} attr {key!r} is {type(value).__name__}"
            )


def test_url_click_asserts_only_a_recorded_ui_action() -> None:
    result = generate_t1566_simulation()
    click = result.events[2]

    assert click.action == "url_click"
    assert click.outcome is EventOutcome.SUCCESS
    # The click is a UI action observation; no network semantics are asserted.
    assert click.attributes.get("destination_domain") == "example.invalid"
    assert "destination_reached" not in click.attributes


def test_url_redirect_never_implies_reaching_the_destination() -> None:
    result = generate_t1566_simulation()
    redirect = result.events[3]

    assert redirect.action == "url_redirect"
    assert redirect.outcome is EventOutcome.SUCCESS
    assert redirect.attributes.get("redirect_inert") == "true"
    assert redirect.attributes.get("destination_reached") == "false"


def test_dns_query_is_inconclusive_and_unresolved() -> None:
    result = generate_t1566_simulation()
    dns = result.events[4]

    assert dns.action == "dns_query"
    assert dns.outcome is EventOutcome.UNKNOWN
    assert dns.attributes.get("resolved") == "false"
    assert dns.attributes.get("resolution_inconclusive") == "true"


def test_url_blocked_is_only_a_policy_decision() -> None:
    result = generate_t1566_simulation()
    blocked = result.events[5]

    assert blocked.action == "url_blocked"
    assert blocked.outcome is EventOutcome.SUCCESS
    assert blocked.attributes.get("decision") == "blocked"
    assert blocked.attributes.get("established") == "false"
    assert blocked.attributes.get("network_effect") == "none"
    assert blocked.attributes.get("defensive_control") == "true"
    # The block is taken by the workstation's web filter, identified via
    # source+attributes without a dedicated sixth entity.
    assert blocked.source == "web_filter"
    assert blocked.attributes.get("control") == "web_filter"


def test_url_blocked_actor_is_a_valid_existing_entity() -> None:
    result = generate_t1566_simulation()
    blocked = result.events[5]

    actor = result.entity_by_identifier("workstation-022")
    assert blocked.actor_entity_id == actor.id


def test_only_reserved_domains_appear() -> None:
    """No real domain or address may appear in the simulation."""
    result = generate_t1566_simulation()
    joined = (
        " ".join(attr for e in result.entities for attr in e.attributes.values())
        + " "
        + " ".join(
            attr
            for event in result.events
            for attr in event.attributes.values()
        )
    )
    identifiers = " ".join(
        [e.identifier for e in result.entities]
        + [str(e.display_name) for e in result.entities]
    )
    # All identifiers/attributes must resolve to the reserved example.invalid
    # domain or be explicitly non-domain (synthetic labels).
    assert "example.invalid" in identifiers
    for token in joined.replace(",", " ").replace(":", " ").split():
        if token.endswith(".invalid"):
            assert token == "example.invalid" or token.endswith("@example.invalid")
    # No real registrable or documentation-routable domain appears.
    for chunk in (joined + " " + identifiers):
        lower = chunk.lower()
        assert ".com" not in lower
        assert ".org" not in lower
        assert ".net" not in lower


def test_generation_performs_no_side_effecting_activity(
    tmp_path, monkeypatch
) -> None:
    """Generation must not open sockets, spawn subprocesses, or touch the
    filesystem."""
    import socket
    import subprocess

    def _raise(*_args, **_kwargs):
        raise AssertionError("generation performed side-effecting activity")

    monkeypatch.setattr(socket, "socket", _raise)
    monkeypatch.setattr(subprocess, "Popen", _raise)
    monkeypatch.setattr(subprocess, "run", _raise)

    monkeypatch.chdir(tmp_path)
    before = {p for p in tmp_path.rglob("*")}

    result = generate_t1566_simulation()

    after = {p for p in tmp_path.rglob("*")}
    assert before == after
    assert len(result.entities) == 5
    assert len(result.events) == 6


def test_events_do_not_assert_compromise_or_impact() -> None:
    """No event carries language asserting compromise, theft, payload, or
    completed network access."""
    result = generate_t1566_simulation()
    prohibited_values = {
        "compromised",
        "attacker",
        "malicious",
        "breach",
        "exfiltrat",
        "exploited",
        "malware",
        "payload",
        "theft",
    }

    for event in result.events:
        joined = " ".join(event.attributes.values()).lower()
        tokens = {t.strip(".,_") for t in joined.split()}
        assert prohibited_values.isdisjoint(tokens), (
            f"event {event.action} carries a prohibited value token"
        )


def test_naive_start_time_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        generate_t1566_simulation(datetime(2026, 10, 1, 9, 0))
