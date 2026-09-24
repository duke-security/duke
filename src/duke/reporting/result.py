"""Typed content model for a deterministic incident report.

:class:`IncidentReport` is an aggregation of the existing, typed workflow
data — the finding, involved entities, investigation timeline and
evidence, the analyst analysis, the dry-run response plan, and the
detection-validation suite — plus the report's own deterministic identity
and timestamp and the analyst-facing narrative fields. It holds no new
telemetry and performs no action; it exists so the Markdown renderer
(``duke.reporting.render``) can deterministically present data that was
already produced by earlier Duke stages.
"""

from uuid import UUID

from pydantic import AwareDatetime, Field

from duke.core import Entity, Evidence, Finding
from duke.core._base import DukeModel
from duke.investigation import TimelineEntry
from duke.response import ResponsePlan
from duke.validation import ValidationSuiteResult


class IncidentReport(DukeModel):
    """A deterministic, advisory incident report derived from workflow data.

    ``report_id`` and ``generated_at`` are deterministic: they derive from
    the underlying finding, not from wall-clock time, so the same input
    always yields the same report identity and timestamp.
    """

    report_id: UUID = Field(
        description="Deterministic report identifier derived from the finding.",
    )
    generated_at: AwareDatetime = Field(
        description=(
            "Deterministic report timestamp derived from `finding.created_at`, "
            "not the wall-clock export time."
        ),
    )
    finding: Finding
    involved_entities: tuple[Entity, ...]
    timeline: tuple[TimelineEntry, ...]
    evidence: tuple[Evidence, ...]
    confirmed_facts: tuple[str, ...]
    analyst_assessments: tuple[str, ...]
    unresolved_questions: tuple[str, ...]
    plan: ResponsePlan
    suite: ValidationSuiteResult
    executive_summary: str = Field(
        description="Cautious, evidence-based narrative summary.",
    )
    scope_summary: str = Field(
        description="What the report covers, bounded to synthetic data.",
    )
    methodology: tuple[str, ...] = Field(
        min_length=1,
        description="The ordered, repeatable steps that produced this report.",
    )
    limitations: tuple[str, ...] = Field(
        min_length=1,
        description="Cautious bounds on what the report does and does not claim.",
    )
    conclusion: str = Field(
        description=(
            "Cautious closing assessment that does not assert compromise, "
            "impact, or exfiltration."
        ),
    )
