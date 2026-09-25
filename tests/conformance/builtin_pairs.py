"""Scenario/expectation pairs shared by conformance tests.

Brings together each scenario under conformance (the built-in T1078 and the
independent probe) with the explicit expectations their authors declare for
them. Importing ``duke.scenarios.builtins`` here is the intended composition
point: this is the one place conformance touches the production built-ins,
so the reusable ``checks``, ``fixture``, and ``probe`` modules stay
implementation-independent.
"""

from typing import TypedDict

from tests.conformance.probe import probe_registration

from duke.scenarios.builtins import t1078_registration
from duke.scenarios.registry import ScenarioRegistration


class ScenarioExpectations(TypedDict):
    """The explicit expectations a scenario author declares for conformance."""

    expected_entity_count: int
    expected_event_count: int
    expected_finding_count: int
    expected_finding_technique: str


SCENARIO_PAIRS: tuple[
    tuple[str, ScenarioRegistration, ScenarioExpectations],
    ...,
] = (
    (
        "T1078",
        t1078_registration(),
        dict(
            expected_entity_count=8,
            expected_event_count=8,
            expected_finding_count=1,
            expected_finding_technique="T1078",
        ),
    ),
    (
        "probe",
        probe_registration(),
        dict(
            expected_entity_count=3,
            expected_event_count=3,
            expected_finding_count=1,
            expected_finding_technique="T9999",
        ),
    ),
)
