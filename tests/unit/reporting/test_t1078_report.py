"""End-to-end tests for deterministic T1078 incident reporting."""

from duke.core import ResponseStatus
from duke.reporting import report_t1078


def _snapshot(artefact):
    return (
        tuple(e.model_dump() for e in artefact.entities),
        tuple(e.model_dump() for e in artefact.events),
    )


def test_source_artefact_is_unchanged(workflow) -> None:
    before = _snapshot(workflow.artefact)

    report_t1078(
        workflow.artefact,
        workflow.finding,
        workflow.result,
        workflow.plan,
        workflow.suite,
    )

    assert _snapshot(workflow.artefact) == before


def test_all_response_actions_are_dry_run_safe(incident_report) -> None:
    actions = incident_report.plan.actions()

    assert len(actions) == 9
    assert all(
        action.dry_run
        and action.requires_approval
        and action.status is ResponseStatus.PLANNED
        for action in actions
    )


def test_narrative_does_not_repeat_finding_title_as_fact(incident_report) -> None:
    title = incident_report.finding.title
    # The analytic label "Compromised identity" must not appear as an
    # established fact in the executive summary or conclusion.
    assert title not in incident_report.executive_summary
    assert title not in incident_report.conclusion


def test_executive_summary_and_conclusion_are_cautious(incident_report) -> None:
    for text in (incident_report.executive_summary, incident_report.conclusion):
        assert "possible valid-account misuse" in text
        assert "not confirmed" in text


def test_report_lists_all_sixteen_validation_cases(incident_report) -> None:
    assert len(incident_report.suite.cases) == 16
    assert incident_report.suite.all_passed is True


def test_unique_event_ids_in_timeline(incident_report) -> None:
    event_ids = [entry.event_id for entry in incident_report.timeline]
    # Duplicate-behaviour cloning must not leak duplicate IDs into the report.
    assert len(event_ids) == len(set(event_ids))
