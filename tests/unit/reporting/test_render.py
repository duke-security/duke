"""Tests for deterministic Markdown rendering of incident reports."""

from duke.reporting import render_incident_report


def test_markdown_is_byte_identical_and_ends_in_one_newline(
    incident_report,
) -> None:
    first = render_incident_report(incident_report)
    second = render_incident_report(incident_report)

    assert first == second
    assert not first.endswith("\n\n")  # exactly one trailing newline
    assert first.endswith("\n")


def test_all_sections_present(markdown) -> None:
    sections = [
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
    ]
    for section in sections:
        assert section in markdown


def test_detection_title_labelled_as_analytic(markdown, incident_report) -> None:
    title = incident_report.finding.title
    assert (
        f"Detection finding title (analytic label; not confirmation): "
        f"\"{title}\""
    ) in markdown


def test_timeline_carries_exact_event_ids(markdown, workflow) -> None:
    for entry in workflow.result.timeline:
        assert str(entry.event_id) in markdown
        assert entry.summary in markdown


def test_evidence_register_lists_ids_and_relationships(markdown, workflow) -> None:
    for evidence in workflow.result.evidence:
        assert str(evidence.id) in markdown
        assert str(evidence.source_event_id) in markdown
        assert evidence.relationship.value in markdown


def test_response_recommendations_labelled_dry_run(markdown) -> None:
    assert "DRY RUN ONLY — APPROVAL REQUIRED — NOT EXECUTED" in markdown
    assert markdown.count("not executed") >= 9


def test_review_only_actions_are_not_irreversible(markdown) -> None:
    # Review-only actions make no system change and must not be labelled
    # "irreversible"; their rollback guidance is "Not applicable".
    assert "Not applicable — no rollback guidance" in markdown
    assert "irreversible" not in markdown


def test_validation_summary_shows_all_cases(markdown, workflow) -> None:
    assert "Detection validation ran once and produced 16 cases." in markdown
    for case in workflow.suite.cases:
        assert case.status.value.upper() in markdown
        assert case.name in markdown
    assert "**Overall: passed** (16 cases)" in markdown


def test_table_content_is_escaped(incident_report) -> None:
    # Introduce pipe/newline characters into a timeline summary and confirm
    # the renderer escapes them so the table structure survives.
    entry = list(incident_report.timeline)[0]
    tampered = entry.model_copy(update={"summary": "row|with pipe\nand newline"})
    report = incident_report.model_copy(
        update={
            "timeline": (
                tampered,
                *incident_report.timeline[1:],
            )
        }
    )

    md = render_incident_report(report)

    assert "row\\|with pipe and newline" in md
