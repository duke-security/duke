"""Deterministic, safe detection for the T1110.003 Password Spraying scenario.

The T1110 simulation emits normalized events that deliberately carry no
``malicious``, ``suspicious``, or ``compromised`` answers, and every spray
event attaches the *source* (the entity performing the attempts) as the actor
and the attempted accounts as targets. ``detect_t1110`` therefore infers a
spray pattern from the *observable* shape of authentication outcomes, never
from a labelled event or a hardcoded account/source identity.

The rule is explainable and fully deterministic:

- It groups events by the acting source (``actor_entity_id``).
- For each source it evaluates every candidate 30-minute window that begins at
  a failed authentication, and selects the **best qualifying window** by
  greatest distinct-account count, then greatest contributing failure count,
  then earliest window start, then deterministic event-ID ordering. This
  prevents an unrelated early failure from hiding a later valid spray burst.
- A window qualifies when it contains at least ``MIN_DISTINCT_ACCOUNTS``
  distinct target accounts that failed. A shared service target (present in
  every failure of the window) never counts as an account; repeated failures
  against an already-counted account do not inflate the count.
- Confidence starts at a base of 60 once the gate passes (so a bare spray is
  still reported), gains points for distinct accounts beyond the threshold,
  and gains ``LATER_SUCCESS_POINTS`` when the same source later successfully
  authenticates, within the window and strictly after the account's failure,
  to an account that previously failed. A success is **supporting evidence
  only**; it does not confirm compromise.
- Severity derives from confidence (medium or high, never critical), because
  investigation is not yet implemented and impact is never confirmed.
- event_ids include every failed authentication inside the selected window
  (including repeated attempts) plus the credited success; entity_ids include
  the source and the distinct sprayed account targets.
"""

from collections.abc import Sequence
from datetime import datetime, timedelta
from uuid import UUID, uuid5

from duke.core import (
    EventOutcome,
    Finding,
    FindingStatus,
    SecurityEvent,
    Severity,
)

_DETECTION_NAME = "password-spraying-window"
_TECHNIQUE_ID = "T1110"
_TITLE = "Password spray against multiple distinct accounts"
_DESCRIPTION = (
    "A single source performed failed authentications against multiple "
    "distinct accounts within a short window. This behaviour is consistent "
    "with password spraying (T1110.003); compromise is not confirmed."
)

# Deterministic identifier namespace so finding IDs are repeatable.
_FINDING_NAMESPACE = UUID("11109000-0000-4000-8000-000000000000")

CORRELATION_WINDOW = timedelta(minutes=30)
MIN_DISTINCT_ACCOUNTS = 5
MAX_CONFIDENCE = 100

# Confidence scoring.
BASE_SPRAY_CONFIDENCE = 60
EXTRA_ACCOUNT_POINTS = 5
MAX_EXTRA_ACCOUNTS = 4
LATER_SUCCESS_POINTS = 15


def _is_failed_auth(event: SecurityEvent) -> bool:
    """Return whether an event is a failed authentication."""
    return event.action == "authenticate" and event.outcome is EventOutcome.FAILURE


def _is_success_auth(event: SecurityEvent) -> bool:
    """Return whether an event is a successful authentication."""
    return event.action == "authenticate" and event.outcome is EventOutcome.SUCCESS


def _distinct_accounts(
    failures: Sequence[SecurityEvent],
) -> tuple[frozenset[UUID], frozenset[UUID]]:
    """Return (distinct sprayed account targets, all targets) for a window.

    A shared service target (present in *every* failure of the window) is
    treated as the identity endpoint one authenticates *through*, never as a
    sprayed account. Repeated failures against an account that is not
    omnipresent still count that account once.
    """
    target_counts: dict[UUID, int] = {}
    all_targets: set[UUID] = set()
    for failure in failures:
        for target in failure.target_entity_ids:
            all_targets.add(target)
            target_counts[target] = target_counts.get(target, 0) + 1

    omnipresent = {
        target for target, count in target_counts.items()
        if count == len(failures)
    }
    account_targets = all_targets - omnipresent
    return frozenset(account_targets), frozenset(all_targets)


def _event_sort_key(event: SecurityEvent) -> tuple[datetime, UUID]:
    """Deterministic ordering for event lists (occurred_at, then id)."""
    return (event.occurred_at, event.id)


def _select_window(
    ordered_failures: Sequence[SecurityEvent],
) -> tuple[tuple[SecurityEvent, ...], frozenset[UUID]] | None:
    """Select the best qualifying spray window, or ``None`` if none qualifies.

    Candidate windows begin at each failed authentication and span
    ``CORRELATION_WINDOW``. A window qualifies when it contains at least
    ``MIN_DISTINCT_ACCOUNTS`` distinct failed-account targets. The best window
    is chosen by: greatest distinct-account count, then greatest contributing
    failure count, then earliest window start, then deterministic event-ID
    ordering of the contributing failures.
    """
    best: tuple[SecurityEvent, ...] | None = None
    best_accounts: frozenset[UUID] = frozenset()
    best_rank: tuple[int, int, datetime, tuple[str, ...]] | None = None

    for index, start_event in enumerate(ordered_failures):
        window_end = start_event.occurred_at + CORRELATION_WINDOW
        window: list[SecurityEvent] = []
        for failure in ordered_failures[index:]:
            if failure.occurred_at > window_end:
                break
            window.append(failure)
        window_tuple = tuple(window)

        accounts, _ = _distinct_accounts(window_tuple)
        distinct = len(accounts)
        if distinct < MIN_DISTINCT_ACCOUNTS:
            continue

        id_order = tuple(
            event.id.__str__()
            for event in sorted(window_tuple, key=lambda e: e.id)
        )
        rank = (distinct, len(window_tuple), start_event.occurred_at, id_order)

        if best_rank is None or rank > best_rank:
            best = window_tuple
            best_accounts = accounts
            best_rank = rank

    if best is None:
        return None
    return best, best_accounts


def _success_credit(
    success_events: Sequence[SecurityEvent],
    window_start: datetime,
    window_end: datetime,
    failed_accounts: frozenset[UUID],
    in_window_failures: Sequence[SecurityEvent],
) -> SecurityEvent | None:
    """Return the credited success event, or ``None``.

    A success earns points only when it: comes from the same source (the
    caller has already grouped by actor), targets an account that previously
    failed within the selected window, occurs strictly after that account's
    failure, and occurs no later than the selected window end. A success
    before the failure, against another account, or outside the window earns
    nothing.
    """
    # Earliest failed time for each account within the window.
    failure_time: dict[UUID, datetime] = {}
    for failure in in_window_failures:
        for account in failed_accounts:
            if account not in failure.target_entity_ids:
                continue
            prior = failure_time.get(account)
            if prior is None or failure.occurred_at < prior:
                failure_time[account] = failure.occurred_at

    for success in sorted(success_events, key=_event_sort_key):
        if not (window_start <= success.occurred_at <= window_end):
            continue
        for target in success.target_entity_ids:
            if target not in failed_accounts:
                continue
            if target not in failure_time:
                continue
            if success.occurred_at > failure_time[target]:
                return success
    return None


def _severity(confidence: int) -> Severity:
    """Derive severity from confidence.

    The spray pattern is a high-confidence behavioural signal, but Duke has
    not confirmed credential validity, account compromise, or impact through
    investigation, so it is never reported as ``critical``.
    """
    if confidence >= 75:
        return Severity.HIGH
    return Severity.MEDIUM


def _detection_details(
    distinct_accounts: int,
    success: SecurityEvent | None,
    confidence: int,
) -> str:
    """Human-readable details including the counted signals."""
    parts = [f"{distinct_accounts} distinct accounts failed from one source"]
    if success is not None:
        parts.append(
            "later success from the same source to a previously failed "
            "account (supporting evidence only)"
        )
    return (
        f"Confidence {confidence}/100 from " + "; ".join(parts) + ". "
        "Compromise is not confirmed."
    )


def _build_finding(
    actor: UUID,
    window: Sequence[SecurityEvent],
    account_targets: frozenset[UUID],
    success: SecurityEvent | None,
    confidence: int,
) -> Finding:
    """Assemble a deterministic, evidence-linked finding."""
    evidence_events = list(window)
    if success is not None:
        evidence_events.append(success)
    evidence_events.sort(key=_event_sort_key)

    entity_ids = sorted({actor} | set(account_targets), key=str)

    return Finding(
        id=uuid5(_FINDING_NAMESPACE, f"{_TECHNIQUE_ID}:{actor}"),
        created_at=evidence_events[0].occurred_at,
        confidence=confidence,
        title=_TITLE,
        description=_DESCRIPTION,
        detection_name=_DETECTION_NAME,
        detection_details=_detection_details(len(account_targets), success, confidence),
        technique_id=_TECHNIQUE_ID,
        severity=_severity(confidence),
        status=FindingStatus.NEW,
        event_ids=[event.id for event in evidence_events],
        entity_ids=entity_ids,
    )


def _evaluate_source(
    actor: UUID,
    events: Sequence[SecurityEvent],
) -> Finding | None:
    """Score one source's failed authentications, or return ``None``."""
    failures = sorted(
        (e for e in events if _is_failed_auth(e)),
        key=_event_sort_key,
    )
    if not failures:
        return None

    selected = _select_window(failures)
    if selected is None:
        return None
    window, account_targets = selected

    window_start = window[0].occurred_at
    window_end = window_start + CORRELATION_WINDOW

    success = _success_credit(
        [e for e in events if _is_success_auth(e)],
        window_start,
        window_end,
        account_targets,
        window,
    )

    confidence = BASE_SPRAY_CONFIDENCE
    confidence += EXTRA_ACCOUNT_POINTS * min(
        len(account_targets) - MIN_DISTINCT_ACCOUNTS,
        MAX_EXTRA_ACCOUNTS,
    )
    if success is not None:
        confidence += LATER_SUCCESS_POINTS
    confidence = min(confidence, MAX_CONFIDENCE)

    return _build_finding(actor, window, account_targets, success, confidence)


def detect_t1110(events: Sequence[SecurityEvent]) -> tuple[Finding, ...]:
    """Infer T1110.003 password-spraying findings from normalized events.

    Events are grouped by source actor; each source that produced a qualifying
    spray window yields a single finding. Empty or benign input returns an
    empty result.
    """
    by_actor: dict[UUID, list[SecurityEvent]] = {}
    for event in events:
        if event.actor_entity_id is not None:
            by_actor.setdefault(event.actor_entity_id, []).append(event)

    findings: list[Finding] = []
    for actor in sorted(by_actor, key=str):
        finding = _evaluate_source(actor, by_actor[actor])
        if finding is not None:
            findings.append(finding)

    return tuple(findings)
