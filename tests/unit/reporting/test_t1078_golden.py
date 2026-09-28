"""Tests that the generalized renderer preserves T1078 byte identity.

The canonical T1078 report, rendered by the current committed (pre-refactor)
implementation, was captured as a checked-in golden fixture. After the
model/renderer generalization these tests assert the refactored output is
byte-identical to that fixture, and that the model's structural role-alignment
rules are enforced.
"""

from pathlib import Path

import pytest

from duke.detection import detect_t1078
from duke.investigation import investigate_t1078
from duke.reporting import (
    IncidentReport,
    render_incident_report,
    report_t1078,
)
from duke.response import plan_t1078_response
from duke.simulation import generate_t1078_simulation
from duke.telemetry import TelemetryArtefact
from duke.validation import validate_t1078

GOLDEN_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "T1078-report-golden.md"
)


def _canonical_report() -> IncidentReport:
    sim = generate_t1078_simulation()
    artefact = TelemetryArtefact(entities=sim.entities, events=sim.events)
    finding = detect_t1078(artefact.events)[0]
    result = investigate_t1078(artefact, finding)
    plan = plan_t1078_response(artefact, result)
    suite = validate_t1078(artefact)
    return report_t1078(artefact, finding, result, plan, suite)


def test_t1078_rendered_output_matches_pre_refactor_golden_bytes() -> None:
    """The generalized renderer reproduces the committed pre-refactor bytes
    exactly (backward byte identity, not merely determinism)."""
    golden = GOLDEN_PATH.read_text(encoding="utf-8")
    markdown = render_incident_report(_canonical_report())

    assert markdown == golden
    assert markdown.endswith("\n")
    assert not markdown.endswith("\n\n")


def test_golden_fixture_is_nonempty_and_stable() -> None:
    golden = GOLDEN_PATH.read_text(encoding="utf-8")
    assert len(golden) > 1000
    assert golden.startswith("# T1078 Incident Report")
    assert "## 12. Conclusion" in golden


# ---- structural role-alignment (correction 3) --------------------------------


def test_entity_roles_align_with_involved_entities() -> None:
    report = _canonical_report()
    assert len(report.entity_roles) == len(report.involved_entities)
    assert all(role.strip() for role in report.entity_roles)


def test_too_few_roles_is_rejected() -> None:
    report = _canonical_report()
    data = report.model_dump()
    data["entity_roles"] = report.entity_roles[:-1]
    with pytest.raises(ValueError):
        IncidentReport.model_validate(data)


def test_too_many_roles_is_rejected() -> None:
    report = _canonical_report()
    data = report.model_dump()
    data["entity_roles"] = report.entity_roles + ("extra",)
    with pytest.raises(ValueError):
        IncidentReport.model_validate(data)


def test_empty_role_is_rejected() -> None:
    report = _canonical_report()
    roles = list(report.entity_roles)
    roles[0] = "   "
    data = report.model_dump()
    data["entity_roles"] = tuple(roles)
    with pytest.raises(ValueError):
        IncidentReport.model_validate(data)
