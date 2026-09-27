"""Deterministic detection-rule validation for T1110.003 Password Spraying.

``validate_t1110`` consumes an existing :class:`TelemetryArtefact` and proves
that the detection → investigation → response-planning pipeline behaves
correctly. For each case it applies a controlled, in-memory mutation (see
:mod:`duke.validation.mutations_t1110` — the source artefact is never
modified and no file or network is touched), reruns the workflow, and records
the expected versus actual outcome.

The canonical T1110 corpus yields a single finding with confidence 80 (the
60-point spray-gate base, +5 for one account over the five-account threshold,
and +15 for the credited later success) at HIGH severity. The ordered
19-case catalogue below exercises the detector's hard boundaries and the
downstream investigation and response pipeline around that baseline.

Every case is deterministic: mutations use fixed ``uuid5`` namespaces and no
wall-clock, results are collected in catalogue order, and a deep snapshot
proves the source artefact is never modified. An ordinary error in a single
case is recorded as a deterministic FAILED case and later cases still run.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

from duke.core import (
    EventOutcome,
    Finding,
    ResponseAction,
    ResponseStatus,
    SecurityEvent,
    Severity,
)
from duke.detection import detect_t1110
from duke.investigation import TimelineEntry, investigate_t1110
from duke.response import plan_t1110_response
from duke.telemetry import TelemetryArtefact
from duke.validation import mutations_t1110 as M
from duke.validation.result import (
    ValidationCase,
    ValidationStatus,
    ValidationSuiteResult,
)

_TECHNIQUE = "T1110"

# A validation check: (artefact, outcome) -> (passed, actual, explanation).
_Check = Callable[[TelemetryArtefact, "_Outcome"], tuple[bool, str, str]]

_BASE = 60
_EXTRA_ONE = 5
_LATER_SUCCESS = 15
_CANONICAL_CONFIDENCE = _BASE + _EXTRA_ONE + _LATER_SUCCESS  # 80

# Response-action counts are deterministic per scenario:
# - 9 when a finding-referenced success account resolves (revoke, step-up, and
#   rotate are present);
# - 6 otherwise (source rate-limit + preserve + four review/monitoring).
_ACTIONS_WITH_SUCCESS = 9
_ACTIONS_WITHOUT_SUCCESS = 6


@dataclass(frozen=True)
class _Outcome:
    """The observable result of running the pipeline over one artefact."""

    finding: Finding | None
    evidence_source_ids: tuple[UUID, ...]
    finding_entity_ids: tuple[UUID, ...]
    involved_entity_ids: tuple[UUID, ...]
    timeline: tuple[TimelineEntry, ...]
    plan_actions: tuple[ResponseAction, ...]
    response_target_ids: tuple[UUID, ...]
    all_actions_safe: bool
    investigation_ran: bool
    response_ran: bool

    @property
    def finding_count(self) -> int:
        return 0 if self.finding is None else 1

    @property
    def confidence(self) -> int | None:
        return None if self.finding is None else self.finding.confidence


def _failure(event: SecurityEvent) -> bool:
    return (
        event.action == "authenticate"
        and event.outcome is EventOutcome.FAILURE
    )


def _success(event: SecurityEvent) -> bool:
    return (
        event.action == "authenticate"
        and event.outcome is EventOutcome.SUCCESS
    )


def _analyze(artefact: TelemetryArtefact) -> _Outcome:
    """Run detection, then investigation and response only when a finding exists."""
    findings = detect_t1110(artefact.events)
    if not findings:
        return _Outcome(None, (), (), (), (), (), (), False, False, False)

    finding = findings[0]
    result = investigate_t1110(artefact, finding)
    plan = plan_t1110_response(artefact, result)

    source_ids = tuple(
        evidence.source_event_id
        for evidence in result.evidence
        if evidence.source_event_id is not None
    )
    return _Outcome(
        finding=finding,
        evidence_source_ids=source_ids,
        finding_entity_ids=tuple(finding.entity_ids),
        involved_entity_ids=tuple(entity.id for entity in result.involved_entities),
        timeline=result.timeline,
        plan_actions=plan.actions(),
        response_target_ids=plan.entity_ids(),
        all_actions_safe=all(
            action.dry_run
            and action.requires_approval
            and action.status is ResponseStatus.PLANNED
            for action in plan.actions()
        ),
        investigation_ran=True,
        response_ran=True,
    )


def _absent_check(reason: str) -> _Check:
    """A no-findings check: no finding and no downstream invocation."""

    def _check(
        _artefact: TelemetryArtefact, outcome: _Outcome
    ) -> tuple[bool, str, str]:
        actual = (
            "investigation/response not invoked"
            if outcome.finding is None
            else f"{outcome.finding_count} finding(s), confidence {outcome.confidence}"
        )
        return (
            outcome.finding is None
            and not outcome.investigation_ran
            and not outcome.response_ran
            and not outcome.plan_actions,
            actual,
            reason,
        )

    return _check


def _positive_check(
    expected_conf: int,
    expected_sev: Severity,
    expected_actions: int,
    reason: str,
) -> _Check:
    """One finding at exact confidence/severity with a safe, deterministic
    downstream pipeline."""

    def _check(
        _artefact: TelemetryArtefact, outcome: _Outcome
    ) -> tuple[bool, str, str]:
        actual = (
            "no findings"
            if outcome.finding is None
            else f"{outcome.finding_count} finding(s), confidence {outcome.confidence}"
        )
        passed = (
            outcome.finding is not None
            and outcome.finding_count == 1
            and outcome.confidence == expected_conf
            and outcome.finding.severity is expected_sev
            and outcome.investigation_ran
            and outcome.response_ran
            and outcome.all_actions_safe
            and len(outcome.plan_actions) == expected_actions
        )
        return passed, actual, reason

    return _check


def _credit_check(expected_conf: int) -> _Check:
    """A success-credit boundary: finding at ``expected_conf`` with six safe
    actions (the uncredited success is not referenced, so no account-specific
    recovery/session actions are proposed)."""

    def _check(
        _artefact: TelemetryArtefact, outcome: _Outcome
    ) -> tuple[bool, str, str]:
        actual = (
            "no findings"
            if outcome.finding is None
            else f"{outcome.finding_count} finding(s), confidence {outcome.confidence}"
        )
        passed = (
            outcome.finding is not None
            and outcome.finding_count == 1
            and outcome.confidence == expected_conf
            and outcome.finding.severity is Severity.MEDIUM
            and outcome.investigation_ran
            and outcome.response_ran
            and outcome.all_actions_safe
            and len(outcome.plan_actions) == _ACTIONS_WITHOUT_SUCCESS
        )
        return (
            passed,
            actual,
            "The later success is not credited (source/account/window rule), so "
            "it earns no confidence and is not referenced by the finding.",
        )

    return _check


# ---- case-specific invariant checks ----------------------------------------


def _check_suspicious_corpus(
    artefact: TelemetryArtefact, outcome: _Outcome
) -> tuple[bool, str, str]:
    actual = (
        "no findings"
        if outcome.finding is None
        else f"{outcome.finding_count} finding(s), confidence {outcome.confidence}, "
        f"{len(outcome.plan_actions)} safe actions, "
        f"{len(outcome.evidence_source_ids)} evidence items"
    )
    failures = [e for e in artefact.events if _failure(e)]
    later_success = M._spray_success(artefact)
    expected_ids = {event.id for event in failures}
    if later_success is not None:
        expected_ids.add(later_success.id)
    passed = (
        outcome.finding is not None
        and outcome.finding_count == 1
        and outcome.confidence == _CANONICAL_CONFIDENCE
        and outcome.finding.severity is Severity.HIGH
        and outcome.investigation_ran
        and outcome.response_ran
        and outcome.all_actions_safe
        and len(outcome.plan_actions) == _ACTIONS_WITH_SUCCESS
        and len(outcome.involved_entity_ids) == 7
        and set(outcome.evidence_source_ids) == set(outcome.finding.event_ids)
        and set(outcome.finding.event_ids) == expected_ids
    )
    return (
        passed,
        actual,
        "The unmodified canonical corpus yields exactly one HIGH finding "
        "(80), one evidence-led investigation, and nine safe response actions.",
    )


def _check_repeats(
    artefact: TelemetryArtefact, outcome: _Outcome
) -> tuple[bool, str, str]:
    actual = (
        "no findings"
        if outcome.finding is None
        else f"{outcome.finding_count} finding(s), confidence {outcome.confidence}"
    )
    failure_ids = {event.id for event in artefact.events if _failure(event)}
    passed = (
        outcome.finding is not None
        and outcome.finding_count == 1
        and outcome.confidence == _BASE + _EXTRA_ONE
        and outcome.finding.severity is Severity.MEDIUM
        # 7 failure events (6 distinct accounts + 1 clone), all retained.
        and len(failure_ids) == 7
        and failure_ids <= set(outcome.finding.event_ids)
        and outcome.all_actions_safe
        and len(outcome.plan_actions) == _ACTIONS_WITHOUT_SUCCESS
    )
    return (
        passed,
        actual,
        "A repeated failure against an already-counted account is retained in "
        "event_ids without inflating the distinct-account count (stays six, "
        "confidence 65).",
    )


def _check_shared_service(
    artefact: TelemetryArtefact, outcome: _Outcome
) -> tuple[bool, str, str]:
    service = M._entity_by_identifier(artefact, "auth-gateway")
    actual = (
        "no findings"
        if outcome.finding is None
        else f"{outcome.finding_count} finding(s), confidence {outcome.confidence}"
    )
    if outcome.finding is None or service is None:
        return False, actual, "Shared-service case produced no resolvable outcome."
    passed = (
        outcome.finding_count == 1
        and outcome.confidence == _CANONICAL_CONFIDENCE
        and outcome.finding.severity is Severity.HIGH
        and service.id not in outcome.finding_entity_ids
        and service.id not in outcome.involved_entity_ids
        and service.id not in outcome.response_target_ids
        and outcome.all_actions_safe
        and len(outcome.plan_actions) == _ACTIONS_WITH_SUCCESS
    )
    return (
        passed,
        actual,
        "A shared service targeted by every failure is never treated as a "
        "sprayed account: it is absent from the finding, the involved entities, "
        "and every response target, while the canonical success is still "
        "credited.",
    )


def _check_unrelated_early(
    artefact: TelemetryArtefact, outcome: _Outcome
) -> tuple[bool, str, str]:
    early = M._entity_by_identifier(artefact, "early.user")
    actual = (
        "no findings"
        if outcome.finding is None
        else f"{outcome.finding_count} finding(s), confidence {outcome.confidence}"
    )
    if outcome.finding is None or early is None:
        return False, actual, "Early-failure case produced no resolvable outcome."
    passed = (
        outcome.finding_count == 1
        and outcome.confidence == _CANONICAL_CONFIDENCE
        and outcome.finding.severity is Severity.HIGH
        and early.id not in outcome.involved_entity_ids
        and outcome.response_ran
        and outcome.all_actions_safe
        and len(outcome.plan_actions) == _ACTIONS_WITH_SUCCESS
    )
    return (
        passed,
        actual,
        "An unrelated early failure does not hide or pollute the later spray: "
        "the later six-account window is selected at confidence 80 and the "
        "early account is not implicated.",
    )


def _check_two_windows(
    artefact: TelemetryArtefact, outcome: _Outcome
) -> tuple[bool, str, str]:
    actual = (
        "no findings"
        if outcome.finding is None
        else f"{outcome.finding_count} finding(s), confidence {outcome.confidence}"
    )
    if outcome.finding is None:
        return False, actual, "Two-window case produced no finding."
    # The earlier burst's events are all before the second burst's start.
    first_burst_start = min(e.occurred_at for e in artefact.events)
    burst1_ids = {
        event.id
        for event in artefact.events
        if event.occurred_at < first_burst_start + timedelta(minutes=30)
    }
    passed = (
        outcome.finding_count == 1
        and outcome.confidence == _BASE
        and outcome.finding.severity is Severity.MEDIUM
        and set(outcome.finding.event_ids) == burst1_ids
        and outcome.response_ran
        and outcome.all_actions_safe
        and len(outcome.plan_actions) == _ACTIONS_WITHOUT_SUCCESS
    )
    return (
        passed,
        actual,
        "Two equally-qualifying windows resolve to the earliest window, whose "
        "exact event IDs are selected, at confidence 60.",
    )


def _check_traceability(outcome: _Outcome) -> tuple[bool, str, str]:
    if outcome.finding is None:
        return (False, "no findings", "No finding to trace evidence against.")
    expected = set(outcome.finding.event_ids)
    timeline_ids = {entry.event_id for entry in outcome.timeline}
    passed = (
        set(outcome.evidence_source_ids) == expected
        and timeline_ids == expected
    )
    return (
        passed,
        f"evidence {len(outcome.evidence_source_ids)} items, "
        f"timeline {len(outcome.timeline)} entries",
        "Evidence and timeline reference exactly the finding's event IDs.",
    )


def _check_deterministic(
    artefact: TelemetryArtefact, outcome: _Outcome
) -> tuple[bool, str, str]:
    rerun = _analyze(artefact)
    return (
        outcome == rerun,
        "stable output",
        "Two identical runs produce identical findings, evidence, involved "
        "entities, and response plan.",
    )


def _check_actions_safe(outcome: _Outcome) -> tuple[bool, str, str]:
    actual = (
        "no actions"
        if not outcome.plan_actions
        else f"{len(outcome.plan_actions)} actions, all_safe={outcome.all_actions_safe}"
    )
    return (
        outcome.all_actions_safe and len(outcome.plan_actions) == _ACTIONS_WITH_SUCCESS,
        actual,
        "Every proposed response action is dry-run, approval-required, and "
        "status=PLANNED.",
    )


# ---- exact ordered 19-case catalogue ---------------------------------------


@dataclass(frozen=True)
class _Case:
    name: str
    mutate: Callable[[TelemetryArtefact], TelemetryArtefact]
    expected: str
    check: Callable[[TelemetryArtefact, _Outcome], tuple[bool, str, str]]


def _specs() -> tuple[_Case, ...]:
    return (
        _Case(
            "suspicious-corpus-unmodified",
            M.identity,
            "1 finding, confidence 80 (HIGH), one investigation result, "
            "9 safe response actions",
            _check_suspicious_corpus,
        ),
        _Case(
            "bare-spray-no-success",
            M.remove_later_success,
            "1 finding, confidence 65 (MEDIUM), 6 safe response actions",
            _positive_check(
                _BASE + _EXTRA_ONE,
                Severity.MEDIUM,
                _ACTIONS_WITHOUT_SUCCESS,
                "Removing the later success still produces the spray finding at "
                "confidence 65 from the six distinct accounts.",
            ),
        ),
        _Case(
            "success-before-failure-no-credit",
            M.move_success_before_failure,
            "1 finding, confidence 65 (MEDIUM), 6 safe response actions",
            _credit_check(_BASE + _EXTRA_ONE),
        ),
        _Case(
            "success-other-account-no-credit",
            M.retarget_success_to_unrelated_account,
            "1 finding, confidence 65 (MEDIUM), 6 safe response actions",
            _credit_check(_BASE + _EXTRA_ONE),
        ),
        _Case(
            "success-outside-window-no-credit",
            M.move_success_outside_window,
            "1 finding, confidence 65 (MEDIUM), 6 safe response actions",
            _credit_check(_BASE + _EXTRA_ONE),
        ),
        _Case(
            "five-distinct-accounts-threshold",
            M.reduce_distinct_accounts(5, True),
            "1 finding, confidence 60 (MEDIUM), 6 safe response actions",
            _positive_check(
                _BASE,
                Severity.MEDIUM,
                _ACTIONS_WITHOUT_SUCCESS,
                "Exactly five distinct accounts meets the threshold at the "
                "60-point floor (bare spray, no success).",
            ),
        ),
        _Case(
            "four-distinct-accounts-below-threshold",
            M.reduce_distinct_accounts(4, True),
            "no findings",
            _absent_check(
                "Four distinct accounts are below the five-account threshold."
            ),
        ),
        _Case(
            "repeated-failures-do-not-inflate",
            M.clone_failure_same_account,
            "1 finding, confidence 65 (MEDIUM), repeat retained in event_ids",
            _check_repeats,
        ),
        _Case(
            "shared-service-not-counted",
            M.add_shared_service,
            "1 finding, confidence 80 (HIGH), 9 safe actions; added service "
            "never implicated",
            _check_shared_service,
        ),
        _Case(
            "mixed-source-actors-no-aggregation",
            M.split_failures_across_sources,
            "no findings",
            _absent_check("Two sources each fail fewer than five accounts."),
        ),
        _Case(
            "single-account-guessing-no-finding",
            M.single_account_guessing,
            "no findings",
            _absent_check("Single-account guessing is not a spray pattern."),
        ),
        _Case(
            "unrelated-early-failure-does-not-hide-later-spray",
            M.add_unrelated_early_failure,
            "1 finding, confidence 80 (HIGH), 9 safe actions; early account "
            "not implicated",
            _check_unrelated_early,
        ),
        _Case(
            "split-beyond-window-no-finding",
            M.spread_failures_beyond_window,
            "no findings",
            _absent_check(
                "No single 30-minute window holds five distinct accounts."
            ),
        ),
        _Case(
            "deterministic-multi-window-selection",
            M.deterministic_two_windows,
            "1 finding, confidence 60 (MEDIUM), earlier window selected, "
            "6 safe actions",
            _check_two_windows,
        ),
        _Case(
            "missing-actor-no-finding",
            M.strip_actors,
            "no findings",
            _absent_check("Events without an actor cannot be correlated."),
        ),
        _Case(
            "benign-no-finding",
            M.benign_only,
            "no findings, no response actions",
            _absent_check(
                "Routine-only activity produces no finding and no plan."
            ),
        ),
        _Case(
            "deterministic-repeatability",
            M.identity,
            "stable output over two identical runs",
            _check_deterministic,
        ),
        _Case(
            "evidence-and-timeline-traceability",
            M.identity,
            "evidence and timeline match the finding's event IDs",
            lambda _a, o: _check_traceability(o),
        ),
        _Case(
            "response-actions-dry-run-safe",
            M.identity,
            "all 9 actions dry-run, approval-required, PLANNED",
            lambda _a, o: _check_actions_safe(o),
        ),
    )


_CASES = _specs()


def _snapshot(artefact: TelemetryArtefact) -> tuple[tuple[object, ...], ...]:
    """A deep, comparable snapshot of an artefact's entities and events."""
    return (
        tuple(entity.model_dump() for entity in artefact.entities),
        tuple(event.model_dump() for event in artefact.events),
    )


def validate_t1110(artefact: TelemetryArtefact) -> ValidationSuiteResult:
    """Validate the T1110 pipeline over an artefact without mutating it.

    Each case builds a fresh in-memory artefact; the supplied artefact is never
    modified, and a deep snapshot before and after proves it. An ordinary error
    in any single case is recorded as a deterministic FAILED case and later
    cases still run; process-control exceptions are re-raised.
    """
    before = _snapshot(artefact)
    cases: list[ValidationCase] = []

    for spec in _CASES:
        mutated = spec.mutate(artefact)
        try:
            outcome = _analyze(mutated)
            passed, actual, explanation = spec.check(mutated, outcome)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:  # noqa: BLE001 - validation must not abort
            passed, actual, explanation = (
                False,
                "case error",
                f"Validation machinery raised: {type(exc).__name__}: {exc}",
            )
        cases.append(
            ValidationCase(
                name=spec.name,
                expected=spec.expected,
                actual=actual,
                status=ValidationStatus.PASS if passed else ValidationStatus.FAIL,
                explanation=explanation,
            )
        )

    after = _snapshot(artefact)
    if after != before:
        raise RuntimeError("validation mutated the source artefact")

    return ValidationSuiteResult(technique_id=_TECHNIQUE, cases=tuple(cases))


__all__ = ["validate_t1110"]
