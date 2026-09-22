"""Tests for packaged scenario loading."""

import pytest

from duke.scenarios import ScenarioLoadError, load_builtin_scenario


def test_loads_t1078_scenario() -> None:
    scenario = load_builtin_scenario("t1078_valid_accounts")

    assert scenario.name == "Valid Accounts: Compromised Identity"
    assert scenario.attack_technique_id == "T1078"
    assert scenario.attack_tactics == [
        "Initial Access",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
    ]
    assert scenario.version == "0.1.0"


def test_loaded_scenario_contains_safety_boundaries() -> None:
    scenario = load_builtin_scenario("t1078_valid_accounts")

    assert scenario.safety_notes
    assert any("synthetic" in note.lower() for note in scenario.safety_notes)
    assert any("does not" in note.lower() for note in scenario.safety_notes)


def test_missing_scenario_is_rejected() -> None:
    with pytest.raises(ScenarioLoadError, match="Scenario not found"):
        load_builtin_scenario("unknown_scenario")


@pytest.mark.parametrize(
    "slug",
    [
        "",
        "../t1078_valid_accounts",
        "t1078-valid-accounts",
        "t1078/valid_accounts",
    ],
)
def test_invalid_scenario_slug_is_rejected(slug: str) -> None:
    with pytest.raises(ScenarioLoadError, match="Invalid scenario slug"):
        load_builtin_scenario(slug)
