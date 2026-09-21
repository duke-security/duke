"""Tests for the Entity domain model."""

import pytest
from pydantic import ValidationError

from duke.core import Entity, EntityType


def test_valid_entity_construction() -> None:
    entity = Entity(entity_type=EntityType.HOST, identifier="workstation-42")

    assert entity.entity_type is EntityType.HOST
    assert entity.identifier == "workstation-42"
    assert entity.display_name is None
    assert entity.attributes == {}


def test_default_id_is_unique() -> None:
    first = Entity(entity_type=EntityType.USER, identifier="alice")
    second = Entity(entity_type=EntityType.USER, identifier="alice")

    assert first.id != second.id


def test_json_round_trip() -> None:
    entity = Entity(
        entity_type=EntityType.CLOUD_RESOURCE,
        identifier="arn:aws:s3:::example-bucket",
        display_name="Example Bucket",
        attributes={"region": "us-east-1"},
    )

    restored = Entity.model_validate_json(entity.model_dump_json())

    assert restored == entity


def test_invalid_entity_type_rejected() -> None:
    with pytest.raises(ValidationError):
        Entity(entity_type="not-a-real-type", identifier="alice")


def test_unknown_field_rejected() -> None:
    with pytest.raises(ValidationError):
        Entity(entity_type=EntityType.USER, identifier="alice", vendor="aws")
