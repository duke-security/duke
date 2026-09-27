"""Tests for deterministic T1110 password-spraying detection validation."""

from pathlib import Path
from uuid import UUID

from duke.detection import detect_t1110
from duke.investigation import investigate_t1110
from duke.response import plan_t1110_response
from duke.simulation import generate_t1110_simulation
from duke.telemetry import TelemetryArtefact
from duke.validation import ValidationStatus, validate_t1110
from duke.validation import t1110 as _t1110

# The exact, ordered 19-case catalogue (correction 10).
EXPECTED_ORDER = (
    "suspicious-corpus-unmodified",
    "bare-spray-no-success",
    "success-before-failure-no-credit",
    "success-other-account-no-credit",
    "success-outside-window-no-credit",
    "five-distinct-accounts-threshold",
    "four-distinct-accounts-below-threshold",
    "repeated-failures-do-not-inflate",
    "shared-service-not-counted",
    "mixed-source-actors-no-aggregation",
    "single-account-guessing-no-finding",
    "unrelated-early-failure-does-not-hide-later-spray",
    "split-beyond-window-no-finding",
    "deterministic-multi-window-selection",
    "missing-actor-no-finding",
    "benign-no-finding",
    "deterministic-repeatability",
    "evidence-and-timeline-traceability",
    "response-actions-dry-run-safe",
)


def _artefact() -> TelemetryArtefact:
    result = generate_t1110_simulation()
    return TelemetryArtefact(entities=result.entities, events=result.events)


def _by_name(suite, name):
    for case in suite.cases:
        if case.name == name:
            return case
    raise AssertionError(f"no case named {name!r}")


def test_canonical_corpus_yields_nineteen_passing_cases_in_exact_order() -> None:
    suite = validate_t1110(_artefact())

    assert len(suite.cases) == 19
    assert [case.name for case in suite.cases] == list(EXPECTED_ORDER)
    assert all(case.status is ValidationStatus.PASS for case in suite.cases)
    assert suite.all_passed is True


def test_case_set_cannot_silently_reorder_or_disappear() -> None:
    from duke.validation.t1110 import _CASES

    assert tuple(case.name for case in _CASES) == EXPECTED_ORDER


def test_output_is_deterministic() -> None:
    first = validate_t1110(_artefact())
    second = validate_t1110(_artefact())

    assert first == second
    assert first.cases == second.cases
    assert [c.status for c in first.cases] == [c.status for c in second.cases]


def test_every_case_reports_expected_actual_and_explanation() -> None:
    suite = validate_t1110(_artefact())
    for case in suite.cases:
        assert case.expected
        assert case.actual
        assert case.explanation


def test_stable_ids_and_no_log_in_expectations() -> None:
    """Expectations must be exact numbers, never placeholder text."""
    suite = validate_t1110(_artefact())
    for case in suite.cases:
        assert "camera corpus" not in case.expected.lower()
        assert "confidence unchanged plot" not in case.explanation.lower()
        assert "video-slice" not in case.expected.lower()
        assert "video slice" not in case.expected.lower()


# ---- core expectations ------------------------------------------------------


def test_canonical_case_asserts_exact_pipeline() -> None:
    suite = validate_t1110(_artefact())
    case = _by_name(suite, "suspicious-corpus-unmodified")

    assert case.status is ValidationStatus.PASS
    assert "confidence 80" in case.actual
    assert "9 safe actions" in case.actual
    assert "7 evidence items" in case.actual


def test_bare_spray_no_success_still_detected() -> None:
    suite = validate_t1110(_artefact())
    case = _by_name(suite, "bare-spray-no-success")
    assert case.status is ValidationStatus.PASS
    assert "confidence 65" in case.actual


def test_success_credit_boundaries_are_exact() -> None:
    suite = validate_t1110(_artefact())
    for name in (
        "success-before-failure-no-credit",
        "success-other-account-no-credit",
        "success-outside-window-no-credit",
    ):
        case = _by_name(suite, name)
        assert case.status is ValidationStatus.PASS, name
        assert "confidence 65" in case.actual, name


def test_threshold_boundary_exact() -> None:
    suite = validate_t1110(_artefact())
    five = _by_name(suite, "five-distinct-accounts-threshold")
    four = _by_name(suite, "four-distinct-accounts-below-threshold")
    assert five.status is ValidationStatus.PASS
    assert "confidence 60" in five.actual
    assert four.status is ValidationStatus.PASS
    assert "not invoked" in four.actual


def test_no_finding_cases_stop_after_detection() -> None:
    """Negative cases assert investigation/response were NOT invoked."""
    suite = validate_t1110(_artefact())
    for name in (
        "four-distinct-accounts-below-threshold",
        "mixed-source-actors-no-aggregation",
        "single-account-guessing-no-finding",
        "split-beyond-window-no-finding",
        "missing-actor-no-finding",
        "benign-no-finding",
    ):
        case = _by_name(suite, name)
        assert case.status is ValidationStatus.PASS, name
        assert "not invoked" in case.actual, name


def test_two_windows_selects_earliest_burst_exactly() -> None:
    suite = validate_t1110(_artefact())
    case = _by_name(suite, "deterministic-multi-window-selection")
    assert case.status is ValidationStatus.PASS
    assert "confidence 60" in case.actual


# ---- source-object immutability (correction 6) ------------------------------


def test_source_artefact_is_structurally_unchanged() -> None:
    artefact = _artefact()
    before = (
        tuple(e.model_dump() for e in artefact.entities),
        tuple(e.model_dump() for e in artefact.events),
    )

    validate_t1110(artefact)

    after = (
        tuple(e.model_dump() for e in artefact.entities),
        tuple(e.model_dump() for e in artefact.events),
    )
    assert after == before


# ---- benign external artefact => failing suite (like T1078) ------------------


def test_benign_artefact_produces_a_failed_suite() -> None:
    result = generate_t1110_simulation()
    benign = TelemetryArtefact(
        entities=result.entities,
        events=result.events[:1],  # only the r.morales baseline
    )

    suite = validate_t1110(benign)

    assert suite.all_passed is False
    assert any(case.status is ValidationStatus.FAIL for case in suite.cases)
    canonical = _by_name(suite, "suspicious-corpus-unmodified")
    assert canonical.status is ValidationStatus.FAIL


# ---- reference integrity (correction 5) -------------------------------------


def _resolve(artefact: TelemetryArtefact) -> tuple[set[UUID], set[UUID]]:
    return (
        {entity.id for entity in artefact.entities},
        {event.id for event in artefact.events},
    )


def test_every_mutated_artefact_references_are_resolvable() -> None:
    """Each mutation's actor/target IDs must resolve to real entities."""
    from duke.validation.t1110 import _CASES

    base = _artefact()
    for case in _CASES:
        mutated = case.mutate(base)
        entity_ids, _event_ids = _resolve(mutated)
        for event in mutated.events:
            actor = event.actor_entity_id
            if actor is not None:
                assert actor in entity_ids, f"{case.name}: unresolved actor"
            for target in event.target_entity_ids:
                assert target in entity_ids, f"{case.name}: unresolved target"


def test_pipeline_references_resolve_in_canonical_validation() -> None:
    """Finding, investigation, and response references all resolve."""
    artefact = _artefact()
    finding = detect_t1110(artefact.events)[0]
    result = investigate_t1110(artefact, finding)
    plan = plan_t1110_response(artefact, result)

    event_ids = {e.id for e in artefact.events}
    entity_ids = {e.id for e in artefact.entities}
    assert set(finding.event_ids) <= event_ids
    assert set(finding.entity_ids) <= entity_ids
    assert {e.id for e in result.involved_entities} <= entity_ids
    assert set(plan.entity_ids()) <= entity_ids


# ---- downstream-not-invoked spies (correction 8) -----------------------------


def test_no_finding_mutation_does_not_invoke_downstream(monkeypatch) -> None:
    from duke.validation import mutations_t1110 as M

    called = {"investigate": 0, "respond": 0}

    def spy_investigate(artefact, finding):
        called["investigate"] += 1
        return investigate_t1110(artefact, finding)

    def spy_respond(artefact, result):
        called["respond"] += 1
        return plan_t1110_response(artefact, result)

    monkeypatch.setattr(_t1110, "investigate_t1110", spy_investigate)
    monkeypatch.setattr(_t1110, "plan_t1110_response", spy_respond)

    mutated = M.single_account_guessing(_artefact())
    outcome = _t1110._analyze(mutated)

    assert outcome.finding is None
    assert called["investigate"] == 0
    assert called["respond"] == 0


# ---- per-case exception handling (correction 7) ------------------------------


def test_single_case_failure_does_not_abort_suite(monkeypatch) -> None:
    """A raising check yields a deterministic FAIL for that case; later cases
    still run, ordering stays intact, and the source artefact is unchanged."""

    def boom_check(artefact, outcome):
        raise ValueError("boom")

    explode = _t1110._Case(
        "explode-case",
        _t1110.M.identity,
        "1 finding, confidence 80 (HIGH)",
        boom_check,
    )
    monkeypatch.setattr(_t1110, "_CASES", (explode, *_t1110._CASES))

    artefact = _artefact()
    suite = _t1110.validate_t1110(artefact)

    # The injected case becomes a deterministic FAIL and does not abort.
    assert suite.cases[0].status is ValidationStatus.FAIL
    assert "boom" in suite.cases[0].explanation
    assert suite.cases[0].actual == "case error"
    # Later cases still ran and the exact 19-case order follows.
    names = [case.name for case in suite.cases]
    assert names[0] == "explode-case"
    assert names[1:] == list(EXPECTED_ORDER)
    assert suite.all_passed is False
    # Source artefact unchanged.
    assert len(artefact.events) == 8


# ---- no-I/O / network inside validation (correction 5 / no-side-effect) -----


def test_validation_package_has_no_file_or_network_side_effects() -> None:
    package_dir = (
        Path(__file__).resolve().parents[2]
        / "src" / "duke" / "validation"
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


def test_no_wall_clock_or_randomness_in_validation() -> None:
    for module in (_t1110, _t1110.M):
        import inspect

        source = inspect.getsource(module)
        assert "uuid4" not in source
        assert "datetime.now" not in source
        assert "datetime.today" not in source
