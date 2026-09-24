"""Deterministic, advisory incident reporting.

Reporting aggregates the existing workflow data — the telemetry artefact,
the ``Finding``, the ``InvestigationResult``, the dry-run ``ResponsePlan``,
and the ``ValidationSuiteResult`` — into a deterministic
:class:`IncidentReport` and renders it as Markdown. It never regenerates
telemetry, never modifies the source artefact, never executes a response
action, and never asserts a confirmed compromise, impact, or exfiltration.
"""

from duke.reporting.export import export_report
from duke.reporting.render import render_incident_report
from duke.reporting.result import IncidentReport
from duke.reporting.t1078 import report_t1078

__all__ = [
    "IncidentReport",
    "export_report",
    "render_incident_report",
    "report_t1078",
]
