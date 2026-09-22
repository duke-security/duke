"""Tests for the safe T1078 simulation."""

from datetime import datetime
from uuid import UUID

import pytest

from duke.simulation import generate_t1078_simulation


def test_generates_expected_event_sequence() -> None:
    result = generate_t1078_simulation()

    assert len(result.entities) == 8
    assert [event.action for event in result.events] == [
        "authenticate",
        "access_application",
        "authenticate",
        "enumerate_repository",
        "read_file",
        "request_privileged_access",
        "create_archive",
        "network_connect",
    ]


def test_simulation_is_deterministic() -> None:
    first = generate_t1078_simulation()
    second = generate_t1078_simulation()

    assert first == second


def test_events_are_chronological() -> None:
    result = generate_t1078_simulation()
    timestamps = [event.occurred_at for event in result.events]

    assert timestamps == sorted(timestamps)


def test_event_relationships_reference_known_entities() -> None:
    result = generate_t1078_simulation()
    entity_ids = {entity.id for entity in result.entities}

    for event in result.events:
        assert isinstance(event.actor_entity_id, UUID)
        assert event.actor_entity_id in entity_ids
        assert set(event.target_entity_ids) <= entity_ids


def test_events_do_not_contain_answer_labels() -> None:
    result = generate_t1078_simulation()
    prohibited_keys = {
        "attack",
        "compromised",
        "malicious",
        "suspicious",
        "threat",
    }

    for event in result.events:
        assert prohibited_keys.isdisjoint(event.attributes)


def test_naive_start_time_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        generate_t1078_simulation(datetime(2026, 9, 22, 9, 0))


def test_entity_lookup_uses_natural_identifier() -> None:
    result = generate_t1078_simulation()

    entity = result.entity_by_identifier("alex.morgan@example.lab")

    assert entity.display_name == "Alex Morgan"


def test_unknown_entity_lookup_is_rejected() -> None:
    result = generate_t1078_simulation()

    with pytest.raises(LookupError, match="Entity not found"):
        result.entity_by_identifier("missing@example.lab")
