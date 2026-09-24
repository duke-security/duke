"""Typed models for Duke's guided learning paths.

Each model is small, metadata-only, and independently validated. A
:class:`LearningPath` is a deterministic, ordered catalogue of
:class:`LearningStep` objects; a step bundles an objective, the Python
concepts it teaches, explanatory prose (including code snippets and CL
command examples), a hands-on :class:`Exercise`, and an explicit safety
note. The package never executes commands, writes learner files, grades
work, or persists progress: everything here is static, in-memory guidance.
"""

from pydantic import Field

from duke.core._base import DukeModel


class LearningObjective(DukeModel):
    """The security objective a single step teaches."""

    statement: str = Field(min_length=1, description="The objective, as a sentence.")


class Hint(DukeModel):
    """One ordered hint shown to a learner."""

    text: str = Field(min_length=1, description="A nudge toward the expected result.")


class KnowledgeCheck(DukeModel):
    """A self-check question with a reference answer (not auto-graded)."""

    prompt: str = Field(min_length=1, description="The self-check question.")
    answer: str = Field(
        min_length=1,
        description=(
            "Reference answer for self-study. There is no grading system in "
            "Duke, so this is shown to the learner, not assessed."
        ),
    )


class Exercise(DukeModel):
    """A hands-on exercise with an expected observable result."""

    title: str = Field(min_length=1)
    instructions: str = Field(min_length=1)
    expected_result: str = Field(
        min_length=1,
        description="The observable result the learner should confirm.",
    )
    hints: tuple[Hint, ...] = Field(
        min_length=1,
        description="Ordered hints (at least one).",
    )
    knowledge_check: KnowledgeCheck


class LearningStep(DukeModel):
    """One guided step in a learning path."""

    id: str = Field(
        min_length=1,
        pattern=r"^[a-z0-9-]+$",
        description="Stable slug used with `duke learn --step`, e.g. 'detection'.",
    )
    ordinal: int = Field(
        ge=1,
        description="Stable position in the path, used for ordering.",
    )
    title: str = Field(min_length=1)
    objective: LearningObjective
    python_concepts: tuple[str, ...] = Field(min_length=1)
    explanation: str = Field(
        min_length=1,
        description=(
            "Explanatory prose and code snippets using documented public "
            "package exports and real CLI syntax."
        ),
    )
    command_examples: tuple[str, ...] = Field(
        min_length=1,
        description="Literal examples of the implemented Duke CLI commands.",
    )
    exercise: Exercise
    safety_note: str = Field(min_length=1)


class LearningPath(DukeModel):
    """A deterministic, ordered catalogue of learning steps."""

    technique_id: str = Field(min_length=1, description="MITRE ATT&CK identifier.")
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    steps: tuple[LearningStep, ...] = Field(min_length=1)

    @property
    def ordered_steps(self) -> tuple[LearningStep, ...]:
        """The steps ordered by their stable ``ordinal``."""
        return tuple(sorted(self.steps, key=lambda step: step.ordinal))

    def step(self, step_id: str) -> LearningStep | None:
        """Return a step by its stable ID, or ``None`` if absent."""
        for step in self.steps:
            if step.id == step_id:
                return step
        return None
