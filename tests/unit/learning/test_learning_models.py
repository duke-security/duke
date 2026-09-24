"""Tests for Duke's guided-learning domain models."""

import pytest
from pydantic import ValidationError

from duke.learning import (
    Exercise,
    Hint,
    KnowledgeCheck,
    LearningObjective,
    LearningPath,
    LearningStep,
)


def _step(step_id: str, ordinal: int, title: str) -> LearningStep:
    return LearningStep(
        id=step_id,
        ordinal=ordinal,
        title=title,
        objective=LearningObjective(statement="An objective."),
        python_concepts=("lists",),
        explanation="Explanation with ```python\nprint([1, 2])\n``` code.",
        command_examples=("duke simulate T1078",),
        exercise=Exercise(
            title="Exercise",
            instructions="Do the thing.",
            expected_result="An observable result.",
            hints=(Hint(text="A nudge"),),
            knowledge_check=KnowledgeCheck(
                prompt="A question?",
                answer="A reference answer.",
            ),
        ),
        safety_note="Synthetic data only; nothing executes.",
    )


def test_learning_path_accepts_minimal_steps() -> None:
    path = LearningPath(
        technique_id="T1078",
        title="Path",
        description="Description.",
        steps=(_step("a", 1, "Step A"), _step("b", 2, "Step B")),
    )

    assert path.technique_id == "T1078"
    assert len(path.steps) == 2


def test_ordered_steps_sort_by_ordinal_not_declaration_order() -> None:
    path = LearningPath(
        technique_id="T1078",
        title="Path",
        description="Description.",
        steps=(_step("b", 2, "Step B"), _step("a", 1, "Step A")),
    )

    assert [s.id for s in path.ordered_steps] == ["a", "b"]


def test_step_lookup_by_id() -> None:
    path = LearningPath(
        technique_id="T1078",
        title="Path",
        description="Description.",
        steps=(_step("alpha", 1, "Step A"), _step("beta", 2, "Step B")),
    )

    assert path.step("beta") is not None
    assert path.step("beta").title == "Step B"  # type: ignore[union-attr]
    assert path.step("missing") is None


def test_step_id_must_match_slug_pattern() -> None:
    with pytest.raises(ValidationError):
        _step("Has Space /  BAD!", 1, "Bad")


def test_step_ordinal_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        _step("zero-ok", 0, "Zero ordinal")


def test_exercise_requires_at_least_one_hint() -> None:
    with pytest.raises(ValidationError):
        Exercise(
            title="Exercise",
            instructions="Do the thing.",
            expected_result="An observable result.",
            hints=(),
            knowledge_check=KnowledgeCheck(prompt="Q?", answer="A."),
        )


def test_fields_reject_unknown_attributes() -> None:
    with pytest.raises(ValidationError):
        LearningStep(  # type: ignore[call-arg]
            id="a",
            ordinal=1,
            title="T",
            objective=LearningObjective(statement="O."),
            python_concepts=("lists",),
            explanation="E.",
            command_examples=("duke simulate T1078",),
            exercise=Exercise(
                title="Ex",
                instructions="I.",
                expected_result="R.",
                hints=(Hint(text="H."),),
                knowledge_check=KnowledgeCheck(prompt="Q?", answer="A."),
            ),
            safety_note="S.",
            unexpected_field="nope",
        )


def test_min_length_enforced_on_core_text_fields() -> None:
    with pytest.raises(ValidationError):
        _step("", 1, "Empty id")
    with pytest.raises(ValidationError):
        _step("a", 1, "")


def test_learning_is_strictly_metadata() -> None:
    """The learning models carry no executable behaviour at all."""
    path = LearningPath(
        technique_id="T1078",
        title="Path",
        description="Description.",
        steps=(_step("a", 1, "Step A"),),
    )
    model = next(iter(path.steps))

    assert not hasattr(model, "run")
    assert not hasattr(model, "execute")
    assert not hasattr(path, "grade")
