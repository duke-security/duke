"""Tests for the safe, deterministic T1110.003 password-spraying detection rule."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5

from duke.core import EventOutcome, FindingStatus, SecurityEvent, Severity
from duke.detection import detect_t1110
from duke.detection.t1110 import (
    CORRELATION_WINDOW,
    MIN_DISTINCT_ACCOUNTS,
)
from duke.simulation import generate_t1110_simulation

_TEST_NS = UUID("1111d000-0000-4000-8000-000000000000")


def _account_id(identifier: str) -> UUID:
    return uuid5(_TEST_NS, f"account:{identifier}")


def _source_id() -> UUID:
    return _account_id("source")


def _service_id() -> UUID:
    return _account_id("service")


def _event(
    action: str,
    outcome: EventOutcome,
    occurred_at: datetime,
    *,
    actor: UUID,
    targets: list[UUID],
    id_hint: str,
    **attributes: str,
) -> SecurityEvent:
    return SecurityEvent(
        id=uuid5(_TEST_NS, f"{id_hint}:{occurred_at.isoformat()}"),
        occurred_at=occurred_at,
        action=action,
        outcome=outcome,
        source="identity_provider",
        actor_entity_id=actor,
        target_entity_ids=targets,
        attributes=attributes,
    )


def _spray_events(
    *,
    start: datetime,
    n_accounts: int,
    spacing: timedelta = timedelta(minutes=2),
    source: UUID | None = None,
    service: UUID | None = None,
    repeated_account: str | None = None,
) -> tuple[SecurityEvent, ...]:
    """Build a password-spray burst: the shared service plus distinct accounts.

    Optionally, ``repeated_account`` causes an account to be failed twice so
    tests can assert repeats do not inflate the distinct-account count.
    """
    source = source or _source_id()
    service = service if service is not None else _service_id()
    events: list[SecurityEvent] = []
    # A benign baseline success first (well before the spray).
    events.append(
        _event(
            "authenticate",
            EventOutcome.SUCCESS,
            start - timedelta(hours=12),
            actor=source,
            targets=[_account_id("benign-user")],
            id_hint="baseline",
        )
    )
    for i in range(n_accounts):
        events.append(
            _event(
                "authenticate",
                EventOutcome.FAILURE,
                start + i * spacing,
                actor=source,
                targets=[service, _account_id(f"acct{i}")],
                id_hint=f"fail-{i}",
            )
        )
    if repeated_account is not None:
        events.append(
            _event(
                "authenticate",
                EventOutcome.FAILURE,
                start + n_accounts * spacing,
                actor=source,
                targets=[service, _account_id(repeated_account)],
                id_hint="fail-repeat",
            )
        )
    return tuple(events)


def _success(
    at: datetime,
    *,
    actor: UUID | None = None,
    target_account: str,
    service: UUID | None = None,
) -> SecurityEvent:
    service = service if service is not None else _service_id()
    actor = actor or _source_id()
    return _event(
        "authenticate",
        EventOutcome.SUCCESS,
        at,
        actor=actor,
        targets=[service, _account_id(target_account)],
        id_hint=f"success-{target_account}",
    )


# ---- true positive on the real corpus --------------------------------------


def test_true_positive_detects_spray_on_real_corpus() -> None:
    result = generate_t1110_simulation()
    findings = detect_t1110(result.events)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.detection_name == "password-spraying-window"
    assert finding.technique_id == "T1110"
    assert finding.status is FindingStatus.NEW
    # 60 base + 5 (one account over the 5 threshold) + 15 (later success).
    assert finding.confidence == 80
    assert finding.severity is Severity.HIGH


def test_success_is_stated_as_supporting_evidence_only() -> None:
    """The finding must never make an affirmative/unqualified claim and must
    explicitly state that a later success is supporting evidence only."""
    result = generate_t1110_simulation()
    finding = detect_t1110(result.events)[0]

    text = " ".join(
        [finding.title, finding.description, finding.detection_details]
    ).lower()

    # Qualified non-claim language must be present and survive.
    assert "compromise is not confirmed" in text
    assert "supporting evidence only" in text

    # It must never assert an affirmative/unqualified conclusion.
    for affirmative in (
        "is compromised",
        "has been compromised",
        "is an attacker",
        "is malicious",
        "exfiltrated",
        "caused impact",
        "valid credential",
        "breached",
    ):
        assert affirmative not in text, f"unqualified claim present: {affirmative!r}"


def test_benign_activity_returns_no_findings() -> None:
    source = _source_id()
    events = (
        _event(
            "authenticate",
            EventOutcome.SUCCESS,
            datetime(2026, 9, 25, 9, 0, tzinfo=UTC),
            actor=source,
            targets=[_account_id("alice")],
            id_hint="ok",
        ),
        _event(
            "access_application",
            EventOutcome.SUCCESS,
            datetime(2026, 9, 25, 9, 5, tzinfo=UTC),
            actor=source,
            targets=[_account_id("app")],
            id_hint="access",
        ),
    )
    assert detect_t1110(events) == ()


def test_empty_input_returns_no_findings() -> None:
    assert detect_t1110(()) == ()


def test_single_account_failure_returns_no_findings() -> None:
    """Single-account guessing (T1110.001-style) never reaches the spray gate."""
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    source = _source_id()
    service = _service_id()
    events = tuple(
        _event(
            "authenticate",
            EventOutcome.FAILURE,
            start + i * timedelta(minutes=2),
            actor=source,
            targets=[service, _account_id("only")],
            id_hint=f"fail-{i}",
        )
        for i in range(6)
    )
    assert detect_t1110(events) == ()


# ---- threshold boundary -----------------------------------------------------


def test_exactly_threshold_accounts_fires() -> None:
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    events = _spray_events(start=start, n_accounts=MIN_DISTINCT_ACCOUNTS)

    findings = detect_t1110(events)

    assert len(findings) == 1
    # Base 60 only (no extra accounts, no success).
    assert findings[0].confidence == 60
    assert findings[0].severity is Severity.MEDIUM


def test_below_threshold_no_finding() -> None:
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    events = _spray_events(start=start, n_accounts=MIN_DISTINCT_ACCOUNTS - 1)
    assert detect_t1110(events) == ()


def test_bare_spray_without_success_still_fires() -> None:
    """A spray campaign is reported even with no later successful login."""
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    events = _spray_events(start=start, n_accounts=6)
    findings = detect_t1110(events)

    assert len(findings) == 1
    # 60 + 5 (one over threshold), no success bonus.
    assert findings[0].confidence == 65
    assert findings[0].severity is Severity.MEDIUM


# ---- window boundary -------------------------------------------------------


def test_overlapping_bursts_at_window_boundary() -> None:
    """Failures exactly at the window end are still in-window."""
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    source = _source_id()
    service = _service_id()
    # 4 accounts early, then 1 account exactly at +30 minutes.
    events = [
        _event(
            "authenticate",
            EventOutcome.FAILURE,
            start + i * timedelta(minutes=2),
            actor=source,
            targets=[service, _account_id(f"a{i}")],
            id_hint=f"fail-{i}",
        )
        for i in range(4)
    ]
    events.append(
        _event(
            "authenticate",
            EventOutcome.FAILURE,
            start + CORRELATION_WINDOW,
            actor=source,
            targets=[service, _account_id("a4")],
            id_hint="fail-boundary",
        )
    )
    assert detect_t1110(tuple(events)) != ()


def test_failures_straddling_window_are_dropped() -> None:
    """A burst whose failures spread beyond the window must not fire (the best
    qualifying window cannot contain all of them)."""
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    source = _source_id()
    service = _service_id()
    events = [
        _event(
            "authenticate",
            EventOutcome.FAILURE,
            start + i * timedelta(minutes=10),
            actor=source,
            targets=[service, _account_id(f"a{i}")],
            id_hint=f"fail-{i}",
        )
        for i in range(6)  # spans 60 minutes
    ]
    assert detect_t1110(tuple(events)) == ()


# ---- sliding-window selection ----------------------------------------------


def test_unrelated_early_failure_does_not_hide_later_spray() -> None:
    """An unrelated early failure must not obscure a valid later burst."""
    start = datetime(2026, 9, 25, 9, 0, tzinfo=UTC)
    source = _source_id()
    service = _service_id()
    early = _event(
        "authenticate",
        EventOutcome.FAILURE,
        start,
        actor=source,
        targets=[service, _account_id("early")],
        id_hint="early",
    )
    # A valid 6-account spray 30+ minutes later (outside the early window).
    spray = _spray_events(
        start=start + timedelta(minutes=60),
        n_accounts=6,
        source=source,
        service=service,
    )
    findings = detect_t1110((early, *spray))

    assert len(findings) == 1
    finding = findings[0]
    # The credited burst is the later spray (6 distinct accounts), not the
    # early failure, which is outside the selected window.
    assert early.id not in finding.event_ids
    assert finding.confidence == 65  # 60 + 5 extra account


def test_multiple_qualifying_windows_select_deterministically() -> None:
    """When several windows qualify, the selection resolves deterministically
    (greatest distinct-account count, then failure count, then earliest)."""
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    source = _source_id()
    service = _service_id()
    # A 5-account burst starting at T0, then a 6-account burst overlapping.
    events = [
        _event(
            "authenticate",
            EventOutcome.FAILURE,
            start + i * timedelta(minutes=2),
            actor=source,
            targets=[service, _account_id(f"x{i}")],
            id_hint=f"burst-{i}",
        )
        for i in range(5)
    ]
    events += [
        _event(
            "authenticate",
            EventOutcome.FAILURE,
            start + timedelta(minutes=8) + i * timedelta(minutes=2),
            actor=source,
            targets=[service, _account_id(f"y{i}")],
            id_hint=f"y-{i}",
        )
        for i in range(6)
    ]
    first = detect_t1110(tuple(events))
    second = detect_t1110(tuple(events))

    assert first == second
    assert len(first) == 1
    # The 6-account window is chosen (greater distinct count).
    assert first[0].confidence >= 60 + 5


# ---- repeated failures ------------------------------------------------------


def test_repeated_failures_retained_in_event_ids_without_inflating_count() -> None:
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    # 6 distinct accounts; one account is failed twice (7 failure events).
    events = _spray_events(
        start=start,
        n_accounts=6,
        repeated_account="acct0",
    )
    findings = detect_t1110(events)

    assert len(findings) == 1
    finding = findings[0]
    # Distinct-account count stays 6 (repeat of acct0 counts once).
    assert finding.confidence == 65  # 60 + 5 (still only one over threshold)
    # The repeated failure is retained in event_ids: 7 failures + no success.
    assert len(finding.event_ids) == 7
    # All failure events are present (no inflation, but no dropping).
    assert len({e.id for e in events if e.outcome is EventOutcome.FAILURE}) == 7
    assert set(finding.event_ids) == {
        e.id for e in events if e.outcome is EventOutcome.FAILURE
    }


# ---- success credit rules ---------------------------------------------------


def test_success_after_failure_is_credited() -> None:
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    events = _spray_events(start=start, n_accounts=6) + (
        _success(at=start + timedelta(minutes=12), target_account="acct0"),
    )
    finding = detect_t1110(events)[0]

    assert finding.confidence == 80  # 60 + 5 + 15
    assert finding.severity is Severity.HIGH
    # The success event is included in event_ids.
    assert len(finding.event_ids) == 7


def test_success_before_failure_gets_no_credit() -> None:
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    # Success against acct0 BEFORE the spray's failure of acct0.
    early_success = _success(at=start - timedelta(minutes=1), target_account="acct0")
    events = (early_success, *_spray_events(start=start, n_accounts=6))
    finding = detect_t1110(events)[0]

    # No success bonus: success preceded the account's failure.
    assert finding.confidence == 65
    assert early_success.id not in finding.event_ids


def test_success_against_other_account_gets_no_credit() -> None:
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    events = _spray_events(start=start, n_accounts=6) + (
        _success(at=start + timedelta(minutes=12), target_account="never-failed"),
    )
    finding = detect_t1110(events)[0]

    assert finding.confidence == 65  # no success bonus


def test_success_outside_window_gets_no_credit() -> None:
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    events = _spray_events(start=start, n_accounts=6) + (
        _success(
            at=start + CORRELATION_WINDOW + timedelta(minutes=1),
            target_account="acct0",
        ),
    )
    finding = detect_t1110(events)[0]

    assert finding.confidence == 65  # success beyond window end not credited


def test_success_exactly_at_window_boundary_is_credited() -> None:
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    success_at_end = _success(
        at=start + CORRELATION_WINDOW,
        target_account="acct0",
    )
    events = _spray_events(start=start, n_accounts=6) + (success_at_end,)
    finding = detect_t1110(events)[0]

    # Success exactly at the window end is still credited.
    assert finding.confidence == 80
    assert success_at_end.id in finding.event_ids


# ---- mixed sources / attribution -------------------------------------------


def test_mixed_sources_do_not_inflate_each_other() -> None:
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    source_a = _account_id("source-a")
    source_b = _account_id("source-b")
    service = _service_id()
    # Each source fails only 3 accounts → neither reaches the threshold.
    events = []
    for s in (source_a, source_b):
        for i in range(3):
            events.append(
                _event(
                    "authenticate",
                    EventOutcome.FAILURE,
                    start + i * timedelta(minutes=2),
                    actor=s,
                    targets=[service, _account_id(f"{s}-{i}")],
                    id_hint=f"{s}-{i}",
                )
            )
    assert detect_t1110(tuple(events)) == ()


def test_events_without_actor_are_ignored() -> None:
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    no_actor = SecurityEvent(
        occurred_at=start,
        action="authenticate",
        outcome=EventOutcome.FAILURE,
        source="identity_provider",
        target_entity_ids=[_account_id("x")],
    )
    assert detect_t1110((no_actor,)) == ()


def test_event_and_entity_attribution_is_scoped() -> None:
    start = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    source = _source_id()
    service = _service_id()
    events = _spray_events(start=start, n_accounts=6, source=source, service=service)
    finding = detect_t1110(events)[0]
    account_ids = {_account_id(f"acct{i}") for i in range(6)}

    # entity_ids include the source and the sprayed accounts, not the service.
    assert source in finding.entity_ids
    assert account_ids <= set(finding.entity_ids)
    assert service not in finding.entity_ids
    # event_ids reference the in-window failed authentications only.
    target_event_ids = {
        e.id for e in events if e.outcome is EventOutcome.FAILURE
    }
    assert set(finding.event_ids) <= target_event_ids


# ---- determinism / robustness ----------------------------------------------


def test_deterministic_output_and_ids() -> None:
    result = generate_t1110_simulation()
    first = detect_t1110(result.events)
    second = detect_t1110(result.events)

    assert first == second
    assert first[0].id == second[0].id
    assert len({f.id for f in first}) == len(first)


def test_severity_never_critical() -> None:
    result = generate_t1110_simulation()
    finding = detect_t1110(result.events)[0]
    assert finding.severity not in (Severity.CRITICAL,)


def test_event_relationships_reference_real_events() -> None:
    result = generate_t1110_simulation()
    finding = detect_t1110(result.events)[0]
    event_ids = {e.id for e in result.events}

    assert set(finding.event_ids) <= event_ids
    assert finding.confidence <= 100


def test_entity_relationships_include_source_and_sprayed_accounts() -> None:
    result = generate_t1110_simulation()
    finding = detect_t1110(result.events)[0]
    id_to_identifier = {e.id: e.identifier for e in result.entities}
    implicated = {id_to_identifier[i] for i in finding.entity_ids}

    assert "host-198.51.100.77" in implicated
    for account in (
        "svc.integration",
        "svc.reports",
        "svc.analytics",
        "svc.etl",
        "d.garcia",
        "a.okafor",
    ):
        assert account in implicated
    # The shared web-portal is context, not implicated.
    assert "web-portal" not in implicated
