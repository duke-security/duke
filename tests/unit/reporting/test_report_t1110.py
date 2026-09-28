"""Tests for deterministic T1110 incident reporting."""

from dataclasses import dataclass
from uuid import UUID

from duke.core import Entity, EntityType, Finding
from duke.detection import detect_t1110
from duke.investigation import InvestigationResult, investigate_t1110
from duke.reporting import IncidentReport, render_incident_report, report_t1110
from duke.response import ResponsePlan, plan_t1110_response
from duke.simulation import generate_t1110_simulation
from duke.telemetry import TelemetryArtefact
from duke.validation import ValidationSuiteResult, validate_t1110

SECTION_HEADERS = (
    "## 1. Report identification",
    "## 2. Executive summary",
    "## 3. Scope and methodology",
    "## 4. Finding",
    "## 5. Involved entities",
    "## 6. Chronological timeline",
    "## 7. Evidence register",
    "## 8. Analysis",
    "## 9. Recommended response",
    "## 10. Validation summary",
    "## 11. Limitations",
    "## 12. Conclusion",
)


@dataclass(frozen=True)
class _Workflow:
    artefact: TelemetryArtefact
    finding: Finding
    result: InvestigationResult
    plan: ResponsePlan
    suite: ValidationSuiteResult


def _workflow() -> _Workflow:
    sim = generate_t1110_simulation()
    artefact = TelemetryArtefact(entities=sim.entities, events=sim.events)
    finding = detect_t1110(artefact.events)[0]
    result = investigate_t1110(artefact, finding)
    plan = plan_t1110_response(artefact, result)
    suite = validate_t1110(artefact)
    return _Workflow(artefact, finding, result, plan, suite)


def _report() -> IncidentReport:
    w = _workflow()
    return report_t1110(w.artefact, w.finding, w.result, w.plan, w.suite)


# ---- structure & determinism -------------------------------------------------


def test_twelve_sections_present_in_order() -> None:
    md = render_incident_report(_report())
    positions = [md.index(section) for section in SECTION_HEADERS]
    assert positions == sorted(positions)


def test_report_identity_is_deterministic() -> None:
    first = _report()
    second = _report()
    assert first.report_id == second.report_id
    assert first.generated_at == first.finding.created_at
    assert first == second


def test_title_and_technique_label_are_t1110() -> None:
    report = _report()
    md = render_incident_report(report)
    assert md.startswith("# T1110 Incident Report")
    assert "Brute Force: Password Spraying" in md
    assert "- Technique: T1110 (Brute Force: Password Spraying)" in md


def test_markdown_is_byte_deterministic_with_one_newline() -> None:
    first = render_incident_report(_report())
    second = render_incident_report(_report())
    assert first == second
    assert first.endswith("\n")
    assert not first.endswith("\n\n")


def test_entire_workflow_aggregated() -> None:
    w = _workflow()
    report = report_t1110(w.artefact, w.finding, w.result, w.plan, w.suite)
    assert report.finding is w.finding
    assert tuple(report.involved_entities) == w.result.involved_entities
    assert tuple(report.timeline) == w.result.timeline
    assert tuple(report.evidence) == w.result.evidence
    assert tuple(report.confirmed_facts) == w.result.confirmed_facts
    assert tuple(report.analyst_assessments) == w.result.analyst_assessments
    assert tuple(report.unresolved_questions) == w.result.unresolved_questions
    assert report.plan is w.plan
    assert report.suite is w.suite


def test_validation_summary_lists_all_nineteen_cases() -> None:
    w = _workflow()
    report = report_t1110(w.artefact, w.finding, w.result, w.plan, w.suite)
    md = render_incident_report(report)
    assert "Detection validation ran once and produced 19 cases." in md
    for case in w.suite.cases:
        assert case.status.value.upper() in md
        assert case.name in md
    assert "**Overall: passed** (19 cases)" in md


# ---- entity roles ------------------------------------------------------------


def test_entity_roles_are_t1110_classified() -> None:
    w = _workflow()
    report = report_t1110(w.artefact, w.finding, w.result, w.plan, w.suite)
    id_to_identifier = {e.id: e.identifier for e in w.artefact.entities}
    by_identifier = {
        id_to_identifier[e.id]: role
        for e, role in zip(
            report.involved_entities, report.entity_roles, strict=True
        )
    }

    assert by_identifier["host-198.51.100.77"] == "source"
    assert by_identifier["svc.reports"] == "sprayed account; later success observed"
    other_accounts = (
        "svc.integration",
        "svc.analytics",
        "svc.etl",
        "d.garcia",
        "a.okafor",
    )
    for account in other_accounts:
        assert by_identifier[account] == "sprayed account"
    # The shared service is not an involved entity and never a sprayed account.
    assert "web-portal" not in by_identifier


def test_ambiguous_entity_uses_neutral_role() -> None:
    """An involved entity that is not the source nor an account renders as the
    neutral role rather than being guessed."""
    sim = generate_t1110_simulation()
    artefact = TelemetryArtefact(entities=sim.entities, events=sim.events)
    finding = detect_t1110(artefact.events)[0]
    result = investigate_t1110(artefact, finding)
    # Add a resolvable unknown-typed involved entity.
    odd = Entity(
        id=UUID("1110f000-0000-4000-8000-0000000000ff"),
        entity_type=EntityType.CLOUD_RESOURCE,
        identifier="odd-resource",
        display_name="Odd",
    )
    result = result.model_copy(
        update={"involved_entities": (*result.involved_entities, odd)}
    )
    plan = plan_t1110_response(artefact, result)
    suite = validate_t1110(artefact)
    report = report_t1110(artefact, finding, result, plan, suite)

    role = report.entity_roles[-1]
    assert role == "involved entity"


# ---- strict aggregation boundaries (correction 6) ----------------------------


def test_unrelated_events_and_entities_never_enter_report_sections() -> None:
    from duke.core import EventOutcome, SecurityEvent

    w = _workflow()
    unrelated_entity = Entity(
        id=UUID("1110f000-0000-4000-8000-0000000000aa"),
        entity_type=EntityType.APPLICATION,
        identifier="unrelated-app",
        display_name="Unrelated",
    )
    unrelated_event = SecurityEvent(
        id=UUID("1110f000-0000-4000-8000-0000000000bb"),
        occurred_at=w.artefact.events[0].occurred_at,
        action="unrelated",
        outcome=EventOutcome.SUCCESS,
        source="other",
        actor_entity_id=unrelated_entity.id,
        attributes={},
    )
    tampered = TelemetryArtefact(
        entities=(*w.artefact.entities, unrelated_entity),
        events=(*w.artefact.events, unrelated_event),
    )
    report = report_t1110(
        tampered, w.finding, w.result, w.plan, w.suite
    )

    md = render_incident_report(report)
    # The unrelated object's identifier and ID must never appear in any report
    # section (the word "unrelated" appears only in a legitimate validation-case
    # name, so we assert on the specific entity identifier/ID instead).
    assert "unrelated-app" not in md
    assert str(unrelated_entity.id) not in md
    # Honest whole-artefact scope counts may reflect the extra entity/event.
    assert f"{len(tampered.events)} security events" in report.scope_summary


# ---- cautious language -------------------------------------------------------


def test_no_affirmative_unqualified_claims() -> None:
    w = _workflow()
    report = report_t1110(w.artefact, w.finding, w.result, w.plan, w.suite)
    # Scan the assertive narrative (executive summary, conclusion, confirmed
    # facts) which must never contain an affirmative overclaim. The limitations
    # and scope sections legitimately enumerate non-claims in negated form
    # ("does not assert that... credentials were stolen"), so they are not
    # scanned for these substrings.
    narrative = " ".join(
        [
            report.executive_summary,
            report.conclusion,
            *report.confirmed_facts,
        ]
    ).lower()

    assert "not confirmed" in narrative
    assert "password spraying" in narrative
    for affirmative in (
        "is compromised",
        "has been compromised",
        "compromise is confirmed",
        "credentials were stolen",
        "the attacker",
        "is malicious",
        "intrusion succeeded",
        "impact did occur",
    ):
        assert affirmative not in narrative, affirmative


def test_finding_title_labelled_as_analytic_not_confirmation() -> None:
    report = _report()
    md = render_incident_report(report)
    assert "Detection finding title (analytic label; not confirmation):" in md
    # The title is not repeated as a confirmed fact.
    assert report.finding.title not in report.confirmed_facts


# ---- response & rollback rendering -------------------------------------------


def test_response_rollback_rendering_is_exact() -> None:
    w = _workflow()
    report = report_t1110(w.artefact, w.finding, w.result, w.plan, w.suite)
    md = render_incident_report(report)
    assert "DRY RUN ONLY — APPROVAL REQUIRED — NOT EXECUTED" in md
    # Reversible action renders its supplied guidance.
    assert "Remove the temporary limit or challenge only after" in md
    # Review-only action renders the neutral no-rollback wording.
    assert "Not applicable — no rollback guidance" in md
    # Review-only actions are never labelled irreversible.
    assert "irreversible" not in md


def test_no_destructive_rollback_wording() -> None:
    """Rollback and purposes must never suggest deleting evidence, restoring
    old credentials, or weakening MFA (the actual wording uses safe negations
    like "never"/"must not")."""
    w = _workflow()
    report = report_t1110(w.artefact, w.finding, w.result, w.plan, w.suite)
    for action in report.plan.actions():
        text = f"{action.purpose} {action.rollback_guidance or ''}".lower()
        # Check for the bare non-negated destructive suggestions only.
        assert "delete the preserved evidence" not in text, action.name
        assert "delete preserved evidence" not in text, action.name
        assert "restore old credentials" not in text, action.name
        assert "restore prior credentials" not in text, action.name
        assert "weaken the mfa baseline" not in text, action.name
