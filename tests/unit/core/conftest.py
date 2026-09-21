"""Shared fixtures for core domain model tests."""

from datetime import UTC, datetime

import pytest


@pytest.fixture
def aware_now() -> datetime:
    """A fixed, timezone-aware datetime for use across model tests."""
    return datetime(2026, 1, 15, 12, 30, tzinfo=UTC)


@pytest.fixture
def naive_now() -> datetime:
    """A fixed, timezone-naive datetime, used to assert it is rejected."""
    return datetime(2026, 1, 15, 12, 30)
