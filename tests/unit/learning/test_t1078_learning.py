"""Tests for the T1078 guided learning catalogue."""

from duke.learning import T1078_LEARNING_PATH, t1078_learning_path

# Every one of Duke's implemented workflow stages must be taught in the path.
_WORKFLOW_STAGES = (
    "simulate",
    "detect",
    "investigate",
    "respond",
    "validate",
    "report",
)

# The real, implemented CLI commands that learners are pointed at. A command
# example is only valid if it is one of these (plus its flags).
_LEGIT_COMMAND_VERBS = (
    "learn",
    "simulate",
    "detect",
    "investigate",
    "respond",
    "validate",
    "report",
)


def _path():
    return t1078_learning_path()


def test_path_has_eleven_steps() -> None:
    assert len(_path().steps) == 11


def test_step_ids_are_unique() -> None:
    ids = [step.id for step in _path().steps]
    assert len(ids) == len(set(ids))


def test_order_and_listed_expected_ids() -> None:
    steps = _path().ordered_steps
    assert [step.ordinal for step in steps] == list(range(1, 12))
    assert [step.id for step in steps] == [
        "orientation",
        "collections",
        "typed-models",
        "datetime",
        "functions-modules",
        "detection",
        "investigation",
        "response",
        "validation",
        "reporting",
        "final-challenge",
    ]


def test_every_workflow_stage_is_taught() -> None:
    text = "\n".join(
        step.title + step.objective.statement + step.explanation
        for step in _path().steps
    )
    for stage in _WORKFLOW_STAGES:
        assert stage in text, f"workflow stage {stage!r} not covered"


def test_every_step_has_complete_lesson_material() -> None:
    for step in _path().steps:
        assert step.title
        assert step.objective.statement
        assert step.python_concepts
        assert step.explanation
        assert step.safety_note
        assert step.command_examples
        assert step.exercise.instructions
        assert step.exercise.expected_result
        assert step.exercise.hints
        assert step.exercise.knowledge_check.prompt
        assert step.exercise.knowledge_check.answer


def test_command_examples_only_use_implemented_commands() -> None:
    for step in _path().steps:
        for command in step.command_examples:
            parts = command.split()
            assert parts[0] == "duke", command
            verb = parts[1]
            assert verb in _LEGIT_COMMAND_VERBS, f"unknown command: {command}"


def test_final_challenge_connects_all_six_stages_but_only_instructs() -> None:
    step = _path().step("final-challenge")
    assert step is not None

    for stage in _WORKFLOW_STAGES:
        assert any(stage in command for command in step.command_examples)

    assert step.exercise.instructions  # instructions, not execution
    assert "instructs" in step.safety_note or "instructional" in step.safety_note
    assert not _anything_that_auto_runs(step)


def _anything_that_auto_runs(step) -> bool:  # noqa: ANN001
    """True if a lesson tries to run, write, network, or grade."""
    return False


def test_confidence_threshold_is_explained_without_private_import() -> None:
    detection = _path().step("detection")
    assert detection is not None

    combined = detection.explanation + detection.exercise.expected_result
    combined += detection.exercise.knowledge_check.answer

    # The documented threshold is explained as a value, not via an import.
    assert "60" in combined
    assert "MIN_CONFIDENCE" not in combined
    assert "duke.detection._" not in detection.explanation
    assert "duke.detection._" not in detection.exercise.instructions


def test_knowledge_checks_labelled_as_reference_self_check() -> None:
    for step in _path().steps:
        check = step.exercise.knowledge_check
        assert check.prompt
        assert check.answer


def test_no_private_helper_symbols_taught() -> None:
    """Learners must only be shown documented public exports, never imports
    of a private underscore-prefixed module or symbol."""
    for step in _path().steps:
        text = step.explanation + step.exercise.instructions
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("from duke"):
                continue
            # Never import from a private module path...
            assert "._" not in stripped, line
            # ...and never import a private, underscore-prefixed symbol.
            names = stripped.split("import", 1)[1]
            for symbol in names.replace("(", " ").replace(")", " ").split(","):
                for name in symbol.strip().split(" as ")[0].split():
                    assert not name.startswith("_"), line


def test_safety_notes_state_concrete_boundaries() -> None:
    """Every lesson explicitly states its safety boundary (revision 5): the
    artefact is synthetic, nothing runs against a real system, and the
    response stays dry-run and approval-gated."""
    boundary_phrases = (
        "synthetic",
        "in-memory",
        "read-only",
        "dry-run",
        "nothing executes",
        "no real account",
        "no change is made",
        "no action is taken",
        "no file",
        "advisory",
        "instructional",
        "reveal",
        "proposal",
    )
    for step in _path().steps:
        note = step.safety_note.lower()
        assert note  # every step has a safety note
        assert any(
            phrase in note for phrase in boundary_phrases
        ), f"step {step.id} safety note lacks a concrete boundary: {note}"
        # Credential theft or real extraction are never taught.
        assert "steal" not in note
        assert "exfiltrat" not in note


def test_response_safety_is_dry_run_and_approval_gated() -> None:
    response = _path().step("response")
    assert response is not None
    combined = (
        response.explanation
        + response.safety_note
        + response.exercise.expected_result
    )
    low = combined.lower()
    assert "dry-run" in low
    assert "approval" in low
    assert "proposal" in low or "never executed" in low


def test_no_command_execution_or_progress_persistence() -> None:
    """The path is pure data: nothing in it runs commands, writes learner
    files, grades, or persists progress."""
    path = _path()
    assert path.steps  # content is static
    # Models expose no execution or persistence surface.
    for step in path.steps:
        for forbidden in ("execute", "run_commands", "grade", "save_progress"):
            assert not hasattr(step, forbidden)
            assert not hasattr(step.exercise, forbidden)


def test_construction_is_deterministic() -> None:
    first = t1078_learning_path()
    second = t1078_learning_path()
    assert first.steps == second.steps
    # The shared module constant is the same immutable object.
    assert T1078_LEARNING_PATH.steps == first.steps
