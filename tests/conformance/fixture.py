"""Typed, test-only conformance fixtures for scenario authoring.

This module provides the canonical inputs and expectations used to run the
reusable scenario-conformance checks. It is test-only and lives under
``tests/``; it must never import from any ``duke.*.t1078`` implementation
module so that the conformance infrastructure stays scenario-independent.

A :class:`ScenarioConformanceFixture` binds a :class:`ScenarioRegistration`
to the concrete data a behavioural check needs: the ``Scenario`` returned by
its lazy ``metadata_loader``, a canonical :class:`TelemetryArtefact` derived
by running its simulation once, and the explicit expectations (entity/event
counts and the detection outcome) that a scenario author declares for it.
Expectations are supplied by the caller — never hardcoded to a technique —
so the same fixture type works for any registered scenario.
"""

from dataclasses import dataclass

from duke.core import Scenario
from duke.scenarios.registry import ScenarioRegistration
from duke.telemetry import TelemetryArtefact


@dataclass(frozen=True)
class ScenarioConformanceFixture:
    """The canonical inputs and expectations for one scenario's conformance."""

    registration: ScenarioRegistration
    metadata: Scenario
    canonical_artefact: TelemetryArtefact
    expected_entity_count: int
    expected_event_count: int
    expected_finding_count: int
    expected_finding_technique: str


def load_conformance_fixture(
    registration: ScenarioRegistration,
    *,
    expected_entity_count: int,
    expected_event_count: int,
    expected_finding_count: int,
    expected_finding_technique: str,
) -> ScenarioConformanceFixture:
    """Build a conformance fixture by loading metadata and running simulation.

    The canonical artefact is produced by the registration's simulation
    capability once when present; otherwise it is empty. Expectations are
    supplied by the caller so the fixture itself never names a technique.
    """
    metadata = registration.metadata_loader()
    simulation = registration.capabilities.simulation
    if simulation is None:
        canonical_artefact = TelemetryArtefact(entities=(), events=())
    else:
        result = simulation()
        canonical_artefact = TelemetryArtefact(
            entities=result.entities,
            events=result.events,
        )
    return ScenarioConformanceFixture(
        registration=registration,
        metadata=metadata,
        canonical_artefact=canonical_artefact,
        expected_entity_count=expected_entity_count,
        expected_event_count=expected_event_count,
        expected_finding_count=expected_finding_count,
        expected_finding_technique=expected_finding_technique,
    )
