"""Shared fixtures for incident-reporting tests."""

from dataclasses import dataclass

import pytest

from duke.core import Finding
from duke.detection import detect_t1078
from duke.investigation import InvestigationResult, investigate_t1078
from duke.reporting import IncidentReport, render_incident_report, report_t1078
from duke.response import ResponsePlan, plan_t1078_response
from duke.simulation import generate_t1078_simulation
from duke.telemetry import TelemetryArtefact
from duke.validation import ValidationSuiteResult, validate_t1078


@dataclass(frozen=True)
class T1078Workflow:
    artefact: TelemetryArtefact
    finding: Finding
    result: InvestigationResult
    plan: ResponsePlan
    suite: ValidationSuiteResult


@pytest.fixture
def artefact() -> TelemetryArtefact:
    result = generate_t1078_simulation()
    return TelemetryArtefact(entities=result.entities, events=result.events)


@pytest.fixture
def workflow(artefact: TelemetryArtefact) -> T1078Workflow:
    finding = detect_t1078(artefact.events)[0]
    result = investigate_t1078(artefact, finding)
    plan = plan_t1078_response(artefact, result)
    suite = validate_t1078(artefact)
    return T1078Workflow(artefact, finding, result, plan, suite)


@pytest.fixture
def incident_report(workflow: T1078Workflow) -> IncidentReport:
    return report_t1078(
        workflow.artefact,
        workflow.finding,
        workflow.result,
        workflow.plan,
        workflow.suite,
    )


@pytest.fixture
def markdown(incident_report: IncidentReport) -> str:
    return render_incident_report(incident_report)
