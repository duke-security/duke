"""Deterministic, safe detection for the T1078 Valid Accounts scenario.

The T1078 simulation emits normalized events that deliberately carry no
``malicious``, ``suspicious``, or ``compromised`` labels (see
``docs/labs/T1078/overview.md``). ``detect_t1078`` therefore infers risk
from the *sequence* and *context* of an actor's behaviour, never from a
labelled event.

The rule is explainable and fully deterministic:

- It requires a prior successful authentication from a **known** network
  and **known** device (the actor's baseline) as a hard gate. New-context
  activity without that baseline produces no finding.
- A later successful login from a **new** network and **unfamiliar**
  device anchors the evaluation and is worth ``NEW_CONTEXT_POINTS`` (25).
- Distinct follow-on behaviours by the same actor within
  ``CORRELATION_WINDOW`` (15 minutes) of that login each add weighted
  confidence points; duplicate behaviour types are counted once.
- Confidence is capped at 100. A finding is produced only at
  ``MIN_CONFIDENCE`` (60) or above, so a new-context login alone never
  reaches the threshold.
- Severity is derived from confidence, but never asserts a confirmed
  compromise: scores map to ``medium`` or ``high``, never ``critical``.
- Entity relationships include the actor and the entities involved in the
  new-context login and follow-on behaviours; the earlier known-good
  baseline device is treated as context and is not implicated.
"""

from collections.abc import Iterable, Sequence
from datetime import timedelta
from uuid import UUID, uuid5

from duke.core import (
    EventOutcome,
    Finding,
    FindingStatus,
    SecurityEvent,
    Severity,
)

_DETECTION_NAME = "compromised-identity-sequence"
_TECHNIQUE_ID = "T1078"
_TITLE = "Compromised identity used from unfamiliar device"
_DESCRIPTION = (
    "An identity with a known-good baseline later logged in from a new "
    "network and unfamiliar device, then performed a correlated set of "
    "suspicious behaviours within the correlation window."
)

# Deterministic identifier namespace so finding IDs are repeatable.
_FINDING_NAMESPACE = UUID("10788000-0000-4000-8000-000000000000")

NEW_CONTEXT_POINTS = 25
CORRELATION_WINDOW = timedelta(minutes=15)
MIN_CONFIDENCE = 60

# Follow-on behaviours and their weighted confidence points. Each type is
# counted at most once, so duplicate events never inflate the score.
_BEHAVIOUR_POINTS: dict[str, int] = {
    "enumerate_repository": 10,
    "restricted_read": 15,
    "privileged_request": 15,
    "archive_create": 10,
    "egress": 15,
}

_BEHAVIOUR_LABELS: dict[str, str] = {
    "enumerate_repository": "repository enumeration",
    "restricted_read": "restricted file access",
    "privileged_request": "privileged-access request",
    "archive_create": "archive creation",
    "egress": "outbound network connection",
}


def _attr(event: SecurityEvent, key: str) -> str | None:
    """Return a normalized event attribute, or ``None`` if absent."""
    return event.attributes.get(key)


def _is_known_good_auth(event: SecurityEvent) -> bool:
    """Return whether an event is a successful login from known context."""
    return (
        event.action == "authenticate"
        and event.outcome is EventOutcome.SUCCESS
        and _attr(event, "network_context") == "known"
        and _attr(event, "device_context") == "known"
    )


def _is_new_context_login(event: SecurityEvent) -> bool:
    """Return whether an event is a successful login from new context."""
    return (
        event.action == "authenticate"
        and event.outcome is EventOutcome.SUCCESS
        and _attr(event, "network_context") == "new"
        and _attr(event, "device_context") == "unfamiliar"
    )


def _behaviour_key(event: SecurityEvent) -> str | None:
    """Map an event to a correlatable behaviour key, or ``None``."""
    if event.action == "enumerate_repository":
        return "enumerate_repository"
    if (
        event.action == "read_file"
        and _attr(event, "data_classification") == "restricted"
    ):
        return "restricted_read"
    if event.action == "request_privileged_access":
        return "privileged_request"
    if event.action == "create_archive":
        return "archive_create"
    if event.action == "network_connect":
        return "egress"
    return None


def _severity(confidence: int) -> Severity:
    """Derive severity from confidence rather than hardcoding it.

    Detection reports a high-confidence behavioural sequence, but Duke has
    not yet confirmed impact, exfiltration, or account compromise through
    investigation, so the severity never reaches ``critical``.
    """
    if confidence >= 75:
        return Severity.HIGH
    return Severity.MEDIUM


def _detection_details(matched: Iterable[str], confidence: int) -> str:
    """Human-readable details including confidence and matched behaviours."""
    parts = ["login from a new network and unfamiliar device"]
    parts.extend(_BEHAVIOUR_LABELS[key] for key in matched)
    return f"Confidence {confidence}/100 from " + ", ".join(parts) + "."


def _evaluate_actor(
    actor: UUID,
    events: Sequence[SecurityEvent],
) -> Finding | None:
    """Score one actor's events and return a finding, or ``None``."""
    ordered = sorted(events, key=lambda event: event.occurred_at)

    baseline = next((e for e in ordered if _is_known_good_auth(e)), None)
    if baseline is None:
        return None

    new_login = next(
        (
            e
            for e in ordered
            if _is_new_context_login(e) and e.occurred_at > baseline.occurred_at
        ),
        None,
    )
    if new_login is None:
        return None

    window_end = new_login.occurred_at + CORRELATION_WINDOW
    follow_ons = [
        e
        for e in ordered
        if new_login.occurred_at < e.occurred_at <= window_end
        and _behaviour_key(e) is not None
    ]

    matched_events: dict[str, SecurityEvent] = {}
    for event in follow_ons:
        key = _behaviour_key(event)
        if key is None:
            continue
        matched_events.setdefault(key, event)

    confidence = min(
        100,
        NEW_CONTEXT_POINTS + sum(_BEHAVIOUR_POINTS[key] for key in matched_events),
    )
    if confidence < MIN_CONFIDENCE:
        return None

    return _build_finding(actor, baseline, new_login, matched_events, confidence)


def _build_finding(
    actor: UUID,
    baseline: SecurityEvent,
    new_login: SecurityEvent,
    matched_events: dict[str, SecurityEvent],
    confidence: int,
) -> Finding:
    """Assemble a deterministic, evidence-linked finding."""
    evidence_events = [baseline, new_login, *matched_events.values()]
    # Implicate the actor, the unfamiliar device from the new-context login,
    # and the targets of the follow-on behaviours. The known-good baseline
    # device stays contextual and is intentionally excluded.
    entity_ids = sorted(
        {actor}
        | set(new_login.target_entity_ids)
        | {
            target
            for event in matched_events.values()
            for target in event.target_entity_ids
        },
        key=str,
    )
    return Finding(
        id=uuid5(_FINDING_NAMESPACE, f"{_TECHNIQUE_ID}:{actor}"),
        created_at=new_login.occurred_at,
        confidence=confidence,
        title=_TITLE,
        description=_DESCRIPTION,
        detection_name=_DETECTION_NAME,
        detection_details=_detection_details(matched_events.keys(), confidence),
        technique_id=_TECHNIQUE_ID,
        severity=_severity(confidence),
        status=FindingStatus.NEW,
        event_ids=[event.id for event in evidence_events],
        entity_ids=entity_ids,
    )


def detect_t1078(events: Sequence[SecurityEvent]) -> tuple[Finding, ...]:
    """Infer T1078 findings from a normalized ``SecurityEvent`` sequence.

    Events are grouped by actor; each actor whose behaviour reaches
    ``MIN_CONFIDENCE`` against a known-good baseline yields a single
    finding. Empty or benign input returns an empty result.
    """
    by_actor: dict[UUID, list[SecurityEvent]] = {}
    for event in events:
        if event.actor_entity_id is not None:
            by_actor.setdefault(event.actor_entity_id, []).append(event)

    findings: list[Finding] = []
    for actor in sorted(by_actor, key=str):
        finding = _evaluate_actor(actor, by_actor[actor])
        if finding is not None:
            findings.append(finding)

    return tuple(findings)
