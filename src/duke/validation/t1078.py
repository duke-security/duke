"""Deterministic detection-rule validation for T1078 Valid Accounts.

``validate_t1078`` consumes an existing :class:`TelemetryArtefact` and
proves that the detection → investigation → response-planning pipeline
behaves correctly. For each case it applies a controlled in-memory
mutation (see :mod:`duke.validation.mutations` — the source artefact is
never modified, and no file or network is touched), reruns the workflow,
and records the expected versus actual outcome.

The canonical T1078 corpus yields a single finding with confidence 90
(new-context login 25 points plus repository enumeration 10, restricted
file access 15, privileged-access request 15, archive creation 10, and
network egress 15) at or above the detection threshold of 60. The cases
exercise the pipeline against that baseline and each mutation around it.
"""

from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from duke.core import Finding, ResponseAction, ResponseStatus
from duke.detection import detect_t1078
from duke.investigation import TimelineEntry, investigate_t1078
from duke.response import plan_t1078_response
from duke.telemetry import TelemetryArtefact
from duke.validation import mutations as M
from duke.validation.result import (
    ValidationCase,
    ValidationStatus,
    ValidationSuiteResult,
)

_TECHNIQUE = "T1078"
_MAX_CONFIDENCE = 90

# The individual follow-on signals and the event action that carries each,
# with the expected post-removal confidence (90 minus the signal's weight).
# Weights from the detection rule are repeated here only as validation
# expectations; the rule's own weights are the source of truth.
_REMOVALS = {
    "remove-repository-enumeration": ("enumerate_repository", 80),
    "remove-restricted-file-access": ("read_file", 75),
    "remove-privileged-access-request": ("request_privileged_access", 75),
    "remove-archive-creation": ("create_archive", 80),
    "remove-network-egress": ("network_connect", 75),
}


@dataclass(frozen=True)
class _Outcome:
    """The observable result of running the workflow over one artefact."""

    finding: Finding | None
    evidence_source_ids: tuple[UUID, ...]
    timeline: tuple[TimelineEntry, ...]
    plan_actions: tuple[ResponseAction, ...]
    all_actions_safe: bool

    @property
    def finding_count(self) -> int:
        return 0 if self.finding is None else 1

    @property
    def confidence(self) -> int | None:
        return None if self.finding is None else self.finding.confidence


def _analyze(artefact: TelemetryArtefact) -> _Outcome:
    """Run detection, investigation, and response planning over an artefact."""
    findings = detect_t1078(artefact.events)
    if not findings:
        return _Outcome(None, (), (), (), True)

    finding = findings[0]
    result = investigate_t1078(artefact, finding)
    plan = plan_t1078_response(artefact, result)
    source_ids = tuple(
        evidence.source_event_id
        for evidence in result.evidence
        if evidence.source_event_id is not None
    )
    return _Outcome(
        finding=finding,
        evidence_source_ids=source_ids,
        timeline=result.timeline,
        plan_actions=plan.actions(),
        all_actions_safe=all(
            action.dry_run
            and action.requires_approval
            and action.status is ResponseStatus.PLANNED
            for action in plan.actions()
        ),
    )


# ---- shared checks ---------------------------------------------------------


def _no_findings_check(
    reason: str,
) -> Callable[[TelemetryArtefact, _Outcome], tuple[bool, str, str]]:
    def _check(
        _artefact: TelemetryArtefact,
        outcome: _Outcome,
    ) -> tuple[bool, str, str]:
        actual = (
            "no findings"
            if outcome.finding is None
            else f"{outcome.finding_count} finding(s), confidence {outcome.confidence}"
        )
        return outcome.finding is None, actual, reason

    return _check


def _confidence_check(
    expected: int,
    reason: str,
) -> Callable[[TelemetryArtefact, _Outcome], tuple[bool, str, str]]:
    def _check(
        _artefact: TelemetryArtefact,
        outcome: _Outcome,
    ) -> tuple[bool, str, str]:
        actual = (
            "no findings"
            if outcome.finding is None
            else f"1 finding, confidence {outcome.confidence}"
        )
        passed = outcome.finding is not None and outcome.confidence == expected
        return passed, actual, reason

    return _check


# ---- individual case checks ------------------------------------------------


def _check_suspicious_corpus(outcome: _Outcome) -> tuple[bool, str, str]:
    passed = (
        outcome.finding is not None
        and outcome.confidence == _MAX_CONFIDENCE
        and len(outcome.plan_actions) == 9
        and outcome.all_actions_safe
    )
    actual = (
        "no findings"
        if outcome.finding is None
        else f"1 finding, confidence {outcome.confidence}, "
        f"{len(outcome.plan_actions)} safe actions"
    )
    return (
        passed,
        actual,
        "The unmodified suspicious corpus yields the canonical high-confidence "
        "finding and a full safe response plan.",
    )


def _check_duplicate_not_inflating(outcome: _Outcome) -> tuple[bool, str, str]:
    actual = (
        "no findings"
        if outcome.finding is None
        else f"1 finding, confidence {outcome.confidence}"
    )
    passed = (
        outcome.finding is not None
        and outcome.confidence == _MAX_CONFIDENCE
        and outcome.finding_count == 1
    )
    return (
        passed,
        actual,
        "Duplicate behaviours are counted once, so confidence stays at 90 "
        "(not inflated toward 100).",
    )


def _check_benign(outcome: _Outcome) -> tuple[bool, str, str]:
    actual = (
        "no findings, no response actions"
        if outcome.finding is None
        else f"{outcome.finding_count} finding(s), confidence {outcome.confidence}"
    )
    passed = outcome.finding is None and not outcome.plan_actions
    return (
        passed,
        actual,
        "Routine-only activity produces no finding and therefore no response plan.",
    )


def _check_deterministic(
    artefact: TelemetryArtefact,
    outcome: _Outcome,
) -> tuple[bool, str, str]:
    rerun = _analyze(artefact)
    passed = outcome == rerun
    return (
        passed,
        "repeatable result",
        "Two identical runs produce identical findings, evidence, and plan.",
    )


def _check_traceability(outcome: _Outcome) -> tuple[bool, str, str]:
    if outcome.finding is None:
        return (False, "no findings", "No finding to trace evidence against.")
    event_ids = set(outcome.finding.event_ids)
    evidence_ok = set(outcome.evidence_source_ids) == event_ids
    ordered = [entry.event_id for entry in outcome.timeline]
    chronological = [entry.event_id for entry in sorted(
        outcome.timeline, key=lambda entry: entry.occurred_at
    )]
    timeline_ok = set(ordered) == event_ids and ordered == chronological
    passed = evidence_ok and timeline_ok
    return (
        passed,
        f"evidence {len(outcome.evidence_source_ids)} items, "
        f"timeline {len(outcome.timeline)} entries",
        "Evidence references exactly the finding's event IDs and the timeline "
        "lists the same events in chronological order.",
    )


def _check_actions_safe(outcome: _Outcome) -> tuple[bool, str, str]:
    actual = (
        "no actions"
        if not outcome.plan_actions
        else f"{len(outcome.plan_actions)} actions, "
        f"all_safe={outcome.all_actions_safe}"
    )
    return (
        outcome.all_actions_safe and len(outcome.plan_actions) == 9,
        actual,
        "Every proposed response action is dry-run, approval-required, and "
        "status=PLANNED.",
    )


# ---- case definitions ------------------------------------------------------


@dataclass(frozen=True)
class _Case:
    name: str
    mutate: M.Mutation
    expected: str
    check: Callable[[TelemetryArtefact, _Outcome], tuple[bool, str, str]]


def _removal_case(name: str) -> _Case:
    action, expected_conf = _REMOVALS[name]
    return _Case(
        name=name,
        mutate=M.remove_action(action),
        expected=f"1 finding, confidence {expected_conf}",
        check=_confidence_check(
            expected_conf,
            f"Removing the {name.removeprefix('remove-').replace('-', ' ')} "
            f"signal drops confidence to {expected_conf}, still above 60.",
        ),
    )


def _specs() -> tuple[_Case, ...]:
    return (
        _Case(
            "suspicious-corpus-unmodified",
            M.identity,
            "1 finding, confidence 90, 9 safe response actions",
            lambda _artefact, outcome: _check_suspicious_corpus(outcome),
        ),
        _Case(
            "missing-known-good-baseline",
            M.remove_known_good_baseline,
            "no findings",
            _no_findings_check(
                "Without the known-good baseline the rule has no anchor and "
                "emits nothing."
            ),
        ),
        _Case(
            "missing-new-context-authentication",
            M.remove_new_context_login,
            "no findings",
            _no_findings_check(
                "Without the new-context login there is no anchor event, so "
                "no finding is produced."
            ),
        ),
        _Case(
            "insufficient-confidence",
            M.reduce_below_threshold,
            "no findings (confidence below 60)",
            _no_findings_check(
                "Removing the high-weight follow-on signals leaves confidence "
                "below the 60 threshold."
            ),
        ),
        _Case(
            "correlation-window-expiry",
            M.expire_correlation_window,
            "no findings",
            _no_findings_check(
                "Follow-on behaviours outside the 15-minute window no longer "
                "contribute, leaving sub-threshold confidence."
            ),
        ),
        _Case(
            "wrong-actor",
            M.reassign_follow_ons_to_other_actor,
            "no findings",
            _no_findings_check(
                "Follow-ons attributed to a different actor without a baseline "
                "do not produce a finding."
            ),
        ),
        _Case(
            "duplicate-behaviours-not-inflating",
            M.duplicate_follow_on,
            "1 finding, confidence 90",
            lambda _artefact, outcome: _check_duplicate_not_inflating(outcome),
        ),
        _removal_case("remove-repository-enumeration"),
        _removal_case("remove-restricted-file-access"),
        _removal_case("remove-privileged-access-request"),
        _removal_case("remove-archive-creation"),
        _removal_case("remove-network-egress"),
        _Case(
            "benign-no-finding",
            M.benign_only_routine,
            "no findings, no response actions",
            lambda _artefact, outcome: _check_benign(outcome),
        ),
        _Case(
            "deterministic-repeatability",
            M.identity,
            "repeatable result",
            _check_deterministic,
        ),
        _Case(
            "evidence-and-timeline-traceability",
            M.identity,
            "evidence and timeline match the finding",
            lambda _artefact, outcome: _check_traceability(outcome),
        ),
        _Case(
            "response-actions-dry-run-safe",
            M.identity,
            "all 9 actions dry-run, approval-required, PLANNED",
            lambda _artefact, outcome: _check_actions_safe(outcome),
        ),
    )


_CASES = _specs()


def _snapshot(artefact: TelemetryArtefact) -> tuple[tuple[object, ...], ...]:
    """A deep, comparable snapshot of an artefact's entities and events."""
    return (
        tuple(entity.model_dump() for entity in artefact.entities),
        tuple(event.model_dump() for event in artefact.events),
    )


def validate_t1078(artefact: TelemetryArtefact) -> ValidationSuiteResult:
    """Validate the T1078 pipeline over an artefact without mutating it.

    Each mutation works on a fresh in-memory :class:`TelemetryArtefact`;
    the supplied artefact is never modified. The function snapshots the
    source before running and raises if validation ever changed it, making
    the immutability guarantee explicit and enforced.
    """
    before = _snapshot(artefact)
    cases: list[ValidationCase] = []

    for spec in _CASES:
        mutated = spec.mutate(artefact)
        outcome = _analyze(mutated)
        passed, actual, explanation = spec.check(mutated, outcome)
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


__all__ = ["validate_t1078"]
