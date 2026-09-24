"""Tests for deterministic rendering of Duke guided-learning content."""

from duke.learning import (
    T1078_LEARNING_PATH,
    Exercise,
    Hint,
    KnowledgeCheck,
    LearningObjective,
    LearningStep,
    render_path,
    render_step,
)
from duke.learning.t1078 import _t1078_path


def test_render_path_is_deterministic() -> None:
    first = render_path(T1078_LEARNING_PATH)
    second = render_path(T1078_LEARNING_PATH)

    assert first == second
    assert "T1078" in first
    assert "Steps" in first


def test_render_path_lists_all_steps_in_order() -> None:
    text = render_path(T1078_LEARNING_PATH)

    path = _t1078_path()
    for step in path.ordered_steps:
        assert f"{step.ordinal}. {step.id}" in text
    # Ordered by ordinal, not declaration order.
    positions = [text.index(f"{s.ordinal}. {s.id}") for s in path.ordered_steps]
    assert positions == sorted(positions)


def test_render_step_is_deterministic_for_every_step() -> None:
    path = _t1078_path()
    for step in path.steps:
        first = render_step(step, path.technique_id)
        second = render_step(step, path.technique_id)
        assert first == second
        assert first.startswith(f"{path.technique_id} — Step {step.ordinal}:")


def test_render_step_contains_objective_concepts_exercise_safety() -> None:
    step = _t1078_path().step("detection")
    assert step is not None
    out = render_step(step, "T1078")

    assert "Objective:" in out
    assert "Python concepts:" in out
    assert "Command examples:" in out
    assert "Exercise:" in out
    assert "Expected observable result:" in out
    assert "Hints:" in out
    assert "Knowledge check:" in out
    assert "Safety note:" in out


def test_knowledge_check_label_is_self_check_not_assessed() -> None:
    out = render_step(_t1078_path().step("detection"), "T1078")
    assert "Reference answer (self-check)" in out
    # It must not be presented as learner-generated or auto-graded.
    assert "graded" not in out.lower()


def test_render_step_escapes_or_bypasses_rich_markup() -> None:
    """Code that looks like Rich markup (e.g. `[text]`) must survive verbatim.

    Brackets, dictionaries, and type annotations in explanations must not be
    swallowed or reformatted. Renderers use literal text, so whatever the
    model holds is what users see.
    """
    # A step whose explanation deliberately mimics Rich tags.
    step = LearningStep(
        id="rich",
        ordinal=1,
        title="Rich-fidelity step",
        objective=LearningObjective(
            statement="Confirm literal rendering of bracket-heavy code."
        ),
        python_concepts=("dictionaries", "annotations"),
        explanation="A dict: {\\n    'a': 1,\\n}\\n"
        "Type: `dict[str, int]`. A tag-like token: [bold].\n"
        "```python\n"
        "box: dict[str, int] = {'k': 1}\n"
        "print(box)\n"
        "```\n",
        command_examples=("duke simulate T1078",),
        exercise=Exercise(
            title="Exercise",
            instructions="Inspect `{'k': 1}` and `box['k']`.",
            expected_result="Prints `{'k': 1}` then `1`.",
            hints=(Hint(text="Read the key with `box['k']`."),),
            knowledge_check=KnowledgeCheck(
                prompt="What does `box['k']` return?",
                answer="1",
            ),
        ),
        safety_note="Synthetic only.",
    )

    out = render_step(step, "T1078")
    # Every bracket-heavy fragment survives untouched.
    for fragment in (
        "dict[str, int]",
        "{'k': 1}",
        "box['k']",
        "[bold]",
        "```python",
    ):
        assert fragment in out
    assert "print(box)" in out