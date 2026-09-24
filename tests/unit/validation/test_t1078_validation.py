"""Tests for deterministic T1078 detection validation."""

from duke.simulation import generate_t1078_simulation
from duke.telemetry import TelemetryArtefact
from duke.validation import ValidationStatus, validate_t1078

_EXPECTED_CASE_NAMES = {
    "suspicious-corpus-unmodified",
    "missing-known-good-baseline",
    "missing-new-context-authentication",
    "insufficient-confidence",
    "correlation-window-expiry",
    "wrong-actor",
    "duplicate-behaviours-not-inflating",
    "remove-repository-enumeration",
    "remove-restricted-file-access",
    "remove-privileged-access-request",
    "remove-archive-creation",
    "remove-network-egress",
    "benign-no-finding",
    "deterministic-repeatability",
    "evidence-and-timeline-traceability",
    "response-actions-dry-run-safe",
}


def _artefact() -> TelemetryArtefact:
    result = generate_t1078_simulation()
    return TelemetryArtefact(entities=result.entities, events=result.events)


def test_canonical_corpus_yields_sixteen_passing_cases() -> None:
    suite = validate_t1078(_artefact())

    assert len(suite.cases) == 16
    assert suite.all_passed is True
    assert all(case.status is ValidationStatus.PASS for case in suite.cases)


def test_case_names_are_explicit_and_complete() -> None:
    suite = validate_t1078(_artefact())

    names = {case.name for case in suite.cases}
    assert names == _EXPECTED_CASE_NAMES
    assert "remove-network-egress" in names


def test_output_is_deterministic() -> None:
    first = validate_t1078(_artefact())
    second = validate_t1078(_artefact())

    assert first == second
    assert first.cases == second.cases


def test_every_case_reports_expected_actual_and_explanation() -> None:
    suite = validate_t1078(_artefact())

    for case in suite.cases:
        assert case.expected
        assert case.actual
        assert case.explanation


def test_source_artefact_is_unchanged_after_validation() -> None:
    artefact = _artefact()
    before = (
        tuple(e.model_dump() for e in artefact.entities),
        tuple(e.model_dump() for e in artefact.events),
    )

    validate_t1078(artefact)

    after = (
        tuple(e.model_dump() for e in artefact.entities),
        tuple(e.model_dump() for e in artefact.events),
    )
    assert after == before


def test_suspicious_corpus_reports_canonical_confidence() -> None:
    suite = validate_t1078(_artefact())
    case = _by_name(suite, "suspicious-corpus-unmodified")

    assert case.status is ValidationStatus.PASS
    assert "confidence 90" in case.actual
    assert "9 safe actions" in case.actual


def test_removal_cases_report_expected_confidence() -> None:
    suite = validate_t1078(_artefact())
    expectations = {
        "remove-repository-enumeration": "80",
        "remove-restricted-file-access": "75",
        "remove-privileged-access-request": "75",
        "remove-archive-creation": "80",
        "remove-network-egress": "75",
    }
    for name, conf in expectations.items():
        case = _by_name(suite, name)
        assert case.status is ValidationStatus.PASS
        assert f"confidence {conf}" in case.actual


def test_duplicate_not_inflating_reports_ninety() -> None:
    suite = validate_t1078(_artefact())
    case = _by_name(suite, "duplicate-behaviours-not-inflating")

    assert case.status is ValidationStatus.PASS
    assert "confidence 90" in case.actual


def test_missing_baseline_case_is_explicit() -> None:
    suite = validate_t1078(_artefact())
    case = _by_name(suite, "missing-known-good-baseline")

    assert case.status is ValidationStatus.PASS
    assert case.actual == "no findings"


def test_benign_artefact_produces_a_failed_suite() -> None:
    """An externally supplied benign artefact cannot satisfy the corpus."""
    result = generate_t1078_simulation()
    benign = TelemetryArtefact(
        entities=result.entities,
        events=result.events[:2],
    )

    suite = validate_t1078(benign)

    assert suite.all_passed is False
    assert any(case.status is ValidationStatus.FAIL for case in suite.cases)
    failing = _by_name(suite, "suspicious-corpus-unmodified")
    assert failing.status is ValidationStatus.FAIL


def _by_name(suite, name):
    for case in suite.cases:
        if case.name == name:
            return case
    raise AssertionError(f"no case named {name!r}")


def test_validation_package_has_no_file_or_network_side_effects() -> None:
    """The validation package must contain no file-writing or network code."""
    from pathlib import Path as _Path

    package_dir = (
        _Path(__file__).parent.parent.parent.parent
        / "src"
        / "duke"
        / "validation"
    )
    forbidden = (
        ".write_",
        "open(",
        "requests",
        "socket",
        "subprocess",
        "urllib",
        "http",
        "Path.write",
        "Path.read",
    )
    for path in sorted(package_dir.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert not any(token in source for token in forbidden), path.name
