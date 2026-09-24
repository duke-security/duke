"""Deterministic rendering for Duke guided learning content.

Rendering is a pure function of the learning model and is fully
deterministic: the same path or step always produces the same string.
Callers render this output as literal text (Rich markup disabled or the
text escaped) so code snippets containing brackets, dictionaries, and type
annotations are never swallowed or reformatted.
"""

from duke.learning.models import LearningPath, LearningStep


def render_path(path: LearningPath) -> str:
    """Render an overview of the whole learning path as plain text.

    The technique identifier, title, description, and an ordered index of
    every step (ordinal, stable id, title) are shown.
    """
    lines = [
        f"{path.technique_id} — {path.title}",
        path.description,
        "",
        "Steps (run `duke learn T1078 --step <id>` for one lesson):",
        "",
    ]
    for step in path.ordered_steps:
        lines.append(f"  {step.ordinal}. {step.id} — {step.title}")
    lines.append("")
    return "\n".join(lines)


def render_step(step: LearningStep, technique_id: str) -> str:
    """Render one full lesson as literal plain text.

    The technique identifier is passed so a lesson is self-contained when
    shown. Everything is verbatim text: no Rich markup interpretation, no
    truncation, no reformatting of code blocks.
    """
    lines = [
        f"{technique_id} — Step {step.ordinal}: {step.title}",
        "",
        f"Objective: {step.objective.statement}",
        "",
        f"Python concepts: {', '.join(step.python_concepts)}",
        "",
        "Explanation:",
        step.explanation,
        "",
        "Command examples:",
    ]
    for command in step.command_examples:
        lines.append(f"  $ {command}")
    exercise = step.exercise
    lines.extend(
        [
            "",
            f"Exercise: {exercise.title}",
            exercise.instructions,
            "",
            f"Expected observable result: {exercise.expected_result}",
            "",
            "Hints:",
        ]
    )
    for hint in exercise.hints:
        lines.append(f"  - {hint.text}")
    lines.extend(
        [
            "",
            f"Knowledge check: {exercise.knowledge_check.prompt}",
            f"Reference answer (self-check): {exercise.knowledge_check.answer}",
            "",
            f"Safety note: {step.safety_note}",
            "",
        ]
    )
    return "\n".join(lines)
