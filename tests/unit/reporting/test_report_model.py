"""Tests for the IncidentReport content model and its derivation."""

from uuid import UUID, uuid5

from duke.reporting import report_t1078

# Deterministic namespace mirroring src/duke/reporting/t1078.py.
_REPORT_NAMESPACE = UUID("1078d000-0000-4000-8000-000000000000")


def test_report_identity_is_derived_from_finding(workflow) -> None:
    report = report_t1078(
        workflow.artefact,
        workflow.finding,
        workflow.result,
        workflow.plan,
        workflow.suite,
    )

    expected = uuid5(_REPORT_NAMESPACE, f"report:{workflow.finding.id}")
    assert report.report_id == expected
    assert report.generated_at == workflow.finding.created_at


def test_report_is_deterministic_across_calls(workflow) -> None:
    first = report_t1078(
        workflow.artefact,
        workflow.finding,
        workflow.result,
        workflow.plan,
        workflow.suite,
    )
    second = report_t1078(
        workflow.artefact,
        workflow.finding,
        workflow.result,
        workflow.plan,
        workflow.suite,
    )

    assert first == second
    assert first.report_id == second.report_id
    assert first.generated_at == second.generated_at


def test_report_consumes_existing_workflow_data(workflow) -> None:
    report = report_t1078(
        workflow.artefact,
        workflow.finding,
        workflow.result,
        workflow.plan,
        workflow.suite,
    )

    assert report.finding is workflow.finding
    assert report.evidence == workflow.result.evidence
    assert report.timeline == workflow.result.timeline
    assert report.involved_entities == workflow.result.involved_entities
    assert report.confirmed_facts == workflow.result.confirmed_facts
    assert report.plan is workflow.plan
    assert report.suite is workflow.suite


def test_report_carries_narrative_fields(incident_report) -> None:
    assert incident_report.executive_summary
    assert incident_report.scope_summary
    assert incident_report.methodology
    assert incident_report.limitations
    assert incident_report.conclusion


def test_report_serializes_and_round_trips(incident_report) -> None:
    restored = type(incident_report).model_validate_json(
        incident_report.model_dump_json()
    )

    assert restored == incident_report
