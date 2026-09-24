"""Tests for validation mutation helpers."""

from duke.simulation import generate_t1078_simulation
from duke.telemetry import TelemetryArtefact
from duke.validation import mutations as M


def _artefact() -> TelemetryArtefact:
    result = generate_t1078_simulation()
    return TelemetryArtefact(entities=result.entities, events=result.events)


def _event_ids(artefact: TelemetryArtefact) -> set:
    return {event.id for event in artefact.events}


def _snapshot(artefact: TelemetryArtefact) -> tuple:
    return (
        tuple(entity.model_dump() for entity in artefact.entities),
        tuple(event.model_dump() for event in artefact.events),
    )


def test_identity_returns_same_artefact() -> None:
    artefact = _artefact()
    assert M.identity(artefact) is artefact


def test_remove_known_good_baseline() -> None:
    artefact = _artefact()
    before = _snapshot(artefact)

    mutated = M.remove_known_good_baseline(artefact)

    assert mutated is not artefact
    baseline = [
        e
        for e in mutated.events
        if e.action == "authenticate"
        and e.attributes.get("network_context") == "known"
    ]
    assert baseline == []
    assert len(mutated.events) == len(artefact.events) - 1
    assert _snapshot(artefact) == before  # source never mutated


def test_remove_new_context_login() -> None:
    artefact = _artefact()
    before = _snapshot(artefact)

    mutated = M.remove_new_context_login(artefact)

    new_login = [
        e
        for e in mutated.events
        if e.action == "authenticate"
        and e.attributes.get("network_context") == "new"
    ]
    assert new_login == []
    assert len(mutated.events) == len(artefact.events) - 1
    assert _snapshot(artefact) == before


def test_reduce_below_threshold() -> None:
    artefact = _artefact()

    mutated = M.reduce_below_threshold(artefact)

    assert all(
        e.action != "read_file"
        and e.action != "request_privileged_access"
        and e.action != "network_connect"
        for e in mutated.events
    )
    # baseline, routine access, new login, enumerate, archive remain
    assert len(mutated.events) == 5


def test_expire_correlation_window_shifts_follow_ons() -> None:
    artefact = _artefact()
    before = {e.id: e.occurred_at for e in artefact.events}

    mutated = M.expire_correlation_window(artefact)

    for event in mutated.events:
        key = _follow_on_key_of(event)
        if key is not None:
            assert event.occurred_at > before[event.id]  # shifted later
        else:
            assert event.occurred_at == before[event.id]  # non-follow-on unchanged
    assert tuple(e.id for e in mutated.events) == tuple(
        e.id for e in artefact.events
    )


def test_reassign_follow_ons_to_other_actor() -> None:
    artefact = _artefact()
    device = next(
        e for e in artefact.entities if e.identifier == "device-unknown-442"
    )

    mutated = M.reassign_follow_ons_to_other_actor(artefact)

    for event in mutated.events:
        if _follow_on_key_of(event) is not None:
            assert event.actor_entity_id == device.id
        else:
            assert event.actor_entity_id is not None  # unchanged non-follow-on


def test_duplicate_follow_on_yields_distinct_deterministic_id() -> None:
    artefact = _artefact()
    original = _event_ids(artefact)
    base_count = len(artefact.events)

    mutated = M.duplicate_follow_on(artefact)
    ids = _event_ids(mutated)

    assert len(mutated.events) == base_count + 1
    # The inserted duplicate has a distinct ID not shared with any original.
    assert (_event_ids(mutated) - original) != set()
    assert len(ids) == base_count + 1  # all IDs distinct, including the clone

    # Deterministic: duplicating twice yields the same new ID.
    second = M.duplicate_follow_on(artefact)
    assert _event_ids(mutated) - original == _event_ids(second) - original


def test_remove_action() -> None:
    artefact = _artefact()

    mutated = M.remove_action("enumerate_repository")(artefact)

    assert all(e.action != "enumerate_repository" for e in mutated.events)
    assert len(mutated.events) == len(artefact.events) - 1


def test_benign_only_routine() -> None:
    artefact = _artefact()

    mutated = M.benign_only_routine(artefact)

    actions = {e.action for e in mutated.events}
    assert actions == {"authenticate", "access_application"}
    assert len(mutated.events) == 2


def test_mutations_never_modify_source() -> None:
    artefact = _artefact()
    before = _snapshot(artefact)
    mutations = [
        M.remove_known_good_baseline,
        M.remove_new_context_login,
        M.reduce_below_threshold,
        M.expire_correlation_window,
        M.reassign_follow_ons_to_other_actor,
        M.duplicate_follow_on,
        M.remove_action("create_archive"),
        M.benign_only_routine,
    ]
    for mutation in mutations:
        mutation(artefact)
        assert _snapshot(artefact) == before


def _follow_on_key_of(event) -> str | None:
    """Local mirror of the detection rule's follow-on key, for assertions."""
    if event.action == "enumerate_repository":
        return "enumerate_repository"
    if (
        event.action == "read_file"
        and event.attributes.get("data_classification") == "restricted"
    ):
        return "restricted_read"
    if event.action == "request_privileged_access":
        return "privileged_request"
    if event.action == "create_archive":
        return "archive_create"
    if event.action == "network_connect":
        return "egress"
    return None
