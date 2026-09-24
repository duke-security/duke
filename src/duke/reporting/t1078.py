"""Deterministic incident reporting for the T1078 Valid Accounts scenario.

``report_t1078`` aggregates the existing workflow data — the telemetry
artefact, the ``Finding``, the evidence-led ``InvestigationResult``, the
dry-run ``ResponsePlan``, and the ``ValidationSuiteResult`` — into a
deterministic :class:`IncidentReport`. It never regenerates telemetry,
never modifies the source artefact, never executes a response action, and
never asserts a confirmed compromise, impact, or exfiltration.

The caller runs ``validate_t1078`` **exactly once** before calling this
function and guarantees that the suite passed and that there is exactly
one finding; this function does not rerun validation (see the CLI).
"""

from uuid import UUID, uuid5

from duke.core import Finding
from duke.investigation import InvestigationResult
from duke.reporting.result import IncidentReport
from duke.response import ResponsePlan
from duke.telemetry import TelemetryArtefact
from duke.validation import ValidationSuiteResult

# Deterministic namespace so report identifiers are repeatable for the same
# finding, mirroring the stable IDs used by earlier pipeline stages.
_REPORT_NAMESPACE = UUID("1078d000-0000-4000-8000-000000000000")

_TECHNIQUE_ID = "T1078"
_TECHNIQUE_LABEL = "valid-account misuse (MITRE ATT&CK T1078)"


def _executive_summary(finding: Finding, suite: ValidationSuiteResult) -> str:
    """A cautious, non-asserting executive summary."""
    return (
        "Behaviour-based detection identified a correlated sequence of activity "
        f"consistent with possible {_TECHNIQUE_LABEL} at confidence "
        f"{finding.confidence}/100. This is a behavioural, analytic signal: "
        "investigation and validation have not confirmed account compromise, "
        f"data exfiltration, or impact. All {len(suite.cases)} "
        "detection-validation cases passed before this report was produced. "
        "The proposed response is dry-run-only and approval-gated; nothing "
        "was executed."
    )


def _scope_summary(artefact: TelemetryArtefact, finding: Finding) -> str:
    """What the report covers, bounded to the supplied synthetic data."""
    return (
        "This report covers the exported normalized telemetry artefact for the "
        f"{_TECHNIQUE_ID} scenario: {len(artefact.events)} security events "
        f"across {len(artefact.entities)} synthetic entities, centred on the "
        f"single detection finding ({finding.detection_name}). It compiles the "
        "finding, its supporting evidence, the chronological timeline, the "
        "evidence-led investigation, the dry-run response plan, and the "
        "detection-validation result. Only synthetic data are involved; no live "
        "system, account, session, permission, file, network, or security "
        "control was accessed or modified, and no response action was executed."
    )


_METHODOLOGY = (
    "Loaded the artefact with load_telemetry_artefact; no telemetry was "
    "regenerated.",
    "Ran behaviour-based detection (detect_t1078) and asserted exactly one "
    "finding.",
    "Ran the evidence-led investigation (investigate_t1078) across the finding's "
    "referenced events.",
    "Ran deterministic response planning (plan_t1078_response) producing "
    "dry-run-only, approval-gated actions grouped by category.",
    "Ran detection validation (validate_t1078) exactly once; the suite must pass "
    "before reporting.",
    "Rendered this deterministic Markdown report from the workflow data above.",
)

_LIMITATIONS = (
    "This report is advisory and derived from synthetic, disposable data in an "
    "isolated lab; it is not a confirmed incident or a final incident report.",
    "It does not assert that an account was compromised, that data was "
    "exfiltrated, or that any impact occurred.",
    "Impact, exfiltration, and account state are unresolved questions, not "
    "established facts.",
    "Response actions are recommendations only: they are dry-run, approval-"
    "required, and were not executed.",
    "Validation asserts internal consistency of Duke's detection rule against "
    "its own corpus and mutations, not real-world precision or recall.",
    "The report timestamp is the deterministic detection timestamp "
    "(finding.created_at), not the wall-clock export time.",
)


def _conclusion(finding: Finding, suite: ValidationSuiteResult) -> str:
    """A cautious closing that does not assert compromise or impact."""
    return (
        f"The observables are consistent with possible {_TECHNIQUE_LABEL} at "
        f"confidence {finding.confidence}/100, and all {len(suite.cases)} "
        "detection-validation cases passed. This remains an analytic "
        "assessment: account compromise, data "
        "exfiltration, and impact are not confirmed, and no response action was "
        "executed. If further investigation supports misuse, follow the "
        "approval-gated, dry-run response recommendations to preserve evidence "
        "and to contain and recover."
    )


def report_t1078(
    artefact: TelemetryArtefact,
    finding: Finding,
    result: InvestigationResult,
    plan: ResponsePlan,
    suite: ValidationSuiteResult,
) -> IncidentReport:
    """Aggregate workflow data into a deterministic :class:`IncidentReport`."""
    return IncidentReport(
        report_id=uuid5(_REPORT_NAMESPACE, f"report:{finding.id}"),
        generated_at=finding.created_at,
        finding=finding,
        involved_entities=result.involved_entities,
        timeline=result.timeline,
        evidence=result.evidence,
        confirmed_facts=result.confirmed_facts,
        analyst_assessments=result.analyst_assessments,
        unresolved_questions=result.unresolved_questions,
        plan=plan,
        suite=suite,
        executive_summary=_executive_summary(finding, suite),
        scope_summary=_scope_summary(artefact, finding),
        methodology=_METHODOLOGY,
        limitations=_LIMITATIONS,
        conclusion=_conclusion(finding, suite),
    )
