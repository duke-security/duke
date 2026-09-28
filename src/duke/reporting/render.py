"""Deterministic Markdown rendering of an :class:`IncidentReport`.

The renderer is a pure function of its input: identical reports produce
byte-identical Markdown. All dynamic values that appear in tables are
escaped so that embedded pipe characters or line breaks in entity names,
descriptions, evidence, and timeline summaries cannot corrupt the table
structure.
"""

from duke.reporting.result import IncidentReport
from duke.response import ResponseCategory

__all__ = ["render_incident_report"]


def _escape(value: str) -> str:
    """Escape a string for safe use inside a Markdown table cell."""
    return value.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


_CATEGORY_TITLES = {
    ResponseCategory.CONTAINMENT: "Containment",
    ResponseCategory.EVIDENCE_PRESERVATION: "Evidence preservation",
    ResponseCategory.INVESTIGATION_FOLLOWUP: "Investigation follow-up",
    ResponseCategory.RECOVERY: "Recovery",
}


def _render_actions(report: IncidentReport) -> str:
    """Render the dry-run response plan grouped by category."""
    lines: list[str] = []
    for index, group in enumerate(report.plan.groups, start=1):
        title = _CATEGORY_TITLES.get(group.category, group.category.value)
        lines.append(f"### 9.{index} {title}")
        lines.append("")
        for action in group.actions:
            rollback = (
                action.rollback_guidance
                if action.supports_rollback and action.rollback_guidance
                else "Not applicable — no rollback guidance"
            )
            lines.append(f"- **{_escape(action.name)}** [risk: {action.risk.value}]")
            lines.append(f"  - Purpose: {_escape(action.purpose)}")
            lines.append(
                "  - Execution: dry run only; approval required; not executed"
            )
            lines.append(f"  - Status: {action.status.value} (not executed)")
            lines.append(f"  - Verification: {_escape(action.verification_guidance)}")
            lines.append(f"  - Rollback: {_escape(rollback)}")
            lines.append("")
    return "\n".join(lines).rstrip()


def render_incident_report(report: IncidentReport) -> str:
    """Render an :class:`IncidentReport` as deterministic Markdown."""
    lines: list[str] = []
    lines.append(f"# {report.title}")
    lines.append("")
    lines.append(
        "> Advisory: this report reads synthetic observables and does not assert "
        "that an account was compromised, that data was exfiltrated, or that "
        "impact occurred. Response actions are dry-run recommendations "
        "requiring human approval; none were executed."
    )
    lines.append("")

    # 1. Report identification
    lines.append("## 1. Report identification")
    lines.append("")
    lines.append(f"- Report ID: `{report.report_id}`")
    lines.append(
        "- Generated (deterministic report timestamp, derived from "
        "`finding.created_at`, not wall-clock export time): "
        f"{report.generated_at.isoformat()}"
    )
    lines.append(
        f"- Technique: {report.finding.technique_id} ({report.technique_label})"
    )
    lines.append("")

    # 2. Executive summary
    lines.append("## 2. Executive summary")
    lines.append("")
    lines.append(report.executive_summary)
    lines.append("")

    # 3. Scope and methodology
    lines.append("## 3. Scope and methodology")
    lines.append("")
    lines.append(report.scope_summary)
    lines.append("")
    lines.append("**Methodology**")
    lines.append("")
    for index, step in enumerate(report.methodology, start=1):
        lines.append(f"{index}. {step}")
    lines.append("")

    # 4. Finding
    lines.append("## 4. Finding")
    lines.append("")
    lines.append(
        "- Detection finding title (analytic label; not confirmation): "
        f"\"{_escape(report.finding.title)}\""
    )
    lines.append(f"- Detection rule: `{report.finding.detection_name}`")
    lines.append(f"- Technique: {report.finding.technique_id}")
    lines.append(f"- Severity: {report.finding.severity.value}")
    lines.append(f"- Status: {report.finding.status.value}")
    lines.append(f"- Confidence: {report.finding.confidence}/100")
    lines.append(f"- Description: {_escape(report.finding.description)}")
    lines.append(f"- Detection rationale: {_escape(report.finding.detection_details)}")
    lines.append("")

    # 5. Involved entities
    lines.append("## 5. Involved entities")
    lines.append("")
    lines.append(report.involved_entities_intro)
    lines.append("")
    lines.append("| Role | Type | Identifier | Display name |")
    lines.append("|---|---|---|---|")
    for index, entity in enumerate(report.involved_entities):
        role = report.entity_roles[index]
        lines.append(
            f"| {_escape(role)} | {_escape(entity.entity_type.value)} | "
            f"{_escape(entity.identifier)} | {_escape(entity.display_name or '')} |"
        )
    lines.append("")

    # 6. Chronological timeline
    lines.append("## 6. Chronological timeline")
    lines.append("")
    lines.append("| # | Timestamp | Event ID | Summary |")
    lines.append("|---|---|---|---|")
    for index, entry in enumerate(report.timeline, start=1):
        lines.append(
            f"| {index} | {entry.occurred_at.isoformat()} | "
            f"{entry.event_id} | {_escape(entry.summary)} |"
        )
    lines.append("")

    # 7. Evidence register
    lines.append("## 7. Evidence register")
    lines.append("")
    lines.append("| Evidence ID | Source event ID | Relationship | Description |")
    lines.append("|---|---|---|---|")
    for evidence in report.evidence:
        source = (
            str(evidence.source_event_id)
            if evidence.source_event_id is not None
            else _escape(evidence.source_artifact_reference or "n/a")
        )
        lines.append(
            f"| {evidence.id} | {source} | {evidence.relationship.value} | "
            f"{_escape(evidence.description)} |"
        )
    lines.append("")

    # 8. Analysis
    lines.append("## 8. Analysis")
    lines.append("")
    lines.append("### 8.1 Confirmed facts")
    lines.append("")
    for fact in report.confirmed_facts:
        lines.append(f"- {_escape(fact)}")
    lines.append("")
    lines.append("### 8.2 Analyst assessments")
    lines.append("")
    for assessment in report.analyst_assessments:
        lines.append(f"- {_escape(assessment)}")
    lines.append("")
    lines.append("### 8.3 Unresolved questions")
    lines.append("")
    for question in report.unresolved_questions:
        lines.append(f"- {_escape(question)}")
    lines.append("")

    # 9. Recommended response
    lines.append("## 9. Recommended response")
    lines.append("")
    lines.append(
        "**DRY RUN ONLY — APPROVAL REQUIRED — NOT EXECUTED.** These are "
        "recommendations, not performed actions."
    )
    lines.append("")
    lines.append(_render_actions(report))
    lines.append("")

    # 10. Validation summary
    lines.append("## 10. Validation summary")
    lines.append("")
    lines.append(
        f"Detection validation ran once and produced {len(report.suite.cases)} "
        "cases."
    )
    lines.append("")
    lines.append("| Status | Case |")
    lines.append("|---|---|")
    for case in report.suite.cases:
        lines.append(f"| {case.status.value.upper()} | {_escape(case.name)} |")
    lines.append("")
    overall = "passed" if report.suite.all_passed else "failed"
    lines.append(f"**Overall: {overall}** ({len(report.suite.cases)} cases)")
    lines.append("")

    # 11. Limitations
    lines.append("## 11. Limitations")
    lines.append("")
    for limitation in report.limitations:
        lines.append(f"- {_escape(limitation)}")
    lines.append("")

    # 12. Conclusion
    lines.append("## 12. Conclusion")
    lines.append("")
    lines.append(report.conclusion)

    return "\n".join(lines).rstrip() + "\n"
