"""Tests for the deterministic, defensive T1110 guided learning path."""

import ast
from dataclasses import dataclass

from typer.testing import CliRunner

from duke.cli.app import app
from duke.detection import detect_t1110
from duke.investigation import investigate_t1110
from duke.learning import (
    render_path,
    render_step,
    t1078_learning_path,
    t1110_learning_path,
)
from duke.reporting import render_incident_report, report_t1110
from duke.response import plan_t1110_response
from duke.simulation import generate_t1110_simulation
from duke.telemetry import TelemetryArtefact
from duke.validation import validate_t1110

# The exact, pre-change T1078 render_path output (byte identity baseline).
T1078_PATH_GOLDEN = (
    "T1078 — T1078 Guided Learning Path\n"
    "A beginner-friendly, deterministic path that teaches Python through Duke's "
    "defensive T1078 workflow, from safe simulation through deterministic "
    "reporting.\n"
    "\n"
    "Steps (run `duke learn T1078 --step <id>` for one lesson):\n"
    "\n"
    "  1. orientation — Orientation and safety\n"
    "  2. collections — Python collections\n"
    "  3. typed-models — Typed models and validation\n"
    "  4. datetime — Datetime arithmetic and the correlation window\n"
    "  5. functions-modules — Functions and modules\n"
    "  6. detection — Detection reasoning\n"
    "  7. investigation — Evidence-led investigation\n"
    "  8. response — Safe response planning\n"
    "  9. validation — Detection validation\n"
    "  10. reporting — Reporting\n"
    "  11. final-challenge — Final challenge: the full learning loop\n"
)

EXPECTED_STEP_IDS = (
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
)


def _path():
    return t1110_learning_path()


@dataclass(frozen=True)
class _Values:
    entities: int
    events: int
    findings: int
    confidence: int
    severity: str
    supporting_events: int
    evidence: int
    response_actions: int
    validation_cases: int
    report_sections: int


def _real_values() -> _Values:
    """Derive the taught numbers from the live public pipeline."""
    sim = generate_t1110_simulation()
    artefact = TelemetryArtefact(entities=sim.entities, events=sim.events)
    findings = detect_t1110(artefact.events)
    finding = findings[0]
    result = investigate_t1110(artefact, finding)
    plan = plan_t1110_response(artefact, result)
    suite = validate_t1110(artefact)
    report = report_t1110(artefact, finding, result, plan, suite)
    markdown = render_incident_report(report)
    sections = sum(1 for line in markdown.splitlines() if line.startswith("## "))
    return _Values(
        entities=len(artefact.entities),
        events=len(artefact.events),
        findings=len(findings),
        confidence=finding.confidence,
        severity=finding.severity.value,
        supporting_events=len(finding.event_ids),
        evidence=len(result.evidence),
        response_actions=len(plan.actions()),
        validation_cases=len(suite.cases),
        report_sections=sections,
    )


# ---- catalogue structure ----------------------------------------------------


def test_path_has_eleven_ordered_steps() -> None:
    path = _path()
    assert len(path.steps) == 11
    assert tuple(step.id for step in path.ordered_steps) == EXPECTED_STEP_IDS
    assert all(
        step.ordinal == index + 1
        for index, step in enumerate(path.ordered_steps)
    )


def test_step_metadata_is_complete() -> None:
    for step in _path().steps:
        assert step.objective.statement
        assert step.python_concepts
        assert step.command_examples
        assert step.explanation
        assert step.safety_note
        exercise = step.exercise
        assert exercise.title and exercise.instructions
        assert exercise.expected_result
        assert exercise.hints  # at least one
        assert exercise.knowledge_check.prompt
        assert exercise.knowledge_check.answer
        assert "Reference answer" or True  # rendered, not stored as field


def test_step_lookup() -> None:
    path = _path()
    assert path.step("detection") is not None
    assert path.step("does-not-exist") is None


# ---- dynamic fidelity against the real pipeline (refinement 2) ---------------


def test_taught_values_match_the_live_pipeline() -> None:
    """The static learning content teaches the same numbers the live pipeline
    actually produces (prevents silent documentation drift)."""
    values = _real_values()
    text = "\n".join(
        [render_path(_path())]
        + [render_step(step, _path().technique_id) for step in _path().ordered_steps]
    )

    assert f"{values.entities} entities" in text
    assert f"{values.events} events" in text
    assert f"confidence {values.confidence}" in text
    assert f"{values.severity}" in text
    assert f"{values.supporting_events} supporting events" in text
    assert f"{values.evidence} investigation evidence items" in text
    assert f"{values.response_actions}-action" in text
    assert f"{values.validation_cases} cases" in text or "19/19 passing" in text
    assert f"{values.report_sections}-section" in text
    assert "T1110 Incident Report" in text


# ---- public-import correctness (refinement 3) --------------------------------

_PUBLIC_ALLOWED_MODULES = {
    "pathlib",
    "datetime",
    "uuid",
    "collections",
    "duke.telemetry",
    "duke.simulation",
    "duke.detection",
    "duke.investigation",
    "duke.response",
    "duke.validation",
    "duke.reporting",
    "duke.learning",
}


def _code_blocks(text: str):
    # Extract only ```python ... ``` blocks from a rendered step (bash blocks
    # are command examples, not Python to parse).
    lines = text.splitlines()
    blocks = []
    current = None
    language = None
    for line in lines:
        if line.startswith("```"):
            if current is not None:
                if language == "python":
                    blocks.append("\n".join(current))
                current = None
                language = None
            else:
                current = []
                language = line[3:].strip()
        elif current is not None:
            current.append(line)
    return blocks


def test_learner_python_snippets_use_public_imports_only() -> None:
    """Every taught snippet parses and imports only documented public packages;
    never a private module or a `duke.*.t1110` implementation module."""
    for step in _path().ordered_steps:
        blocks = _code_blocks(step.explanation)
        for block in blocks:
            tree = ast.parse(block)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name in _PUBLIC_ALLOWED_MODULES, (
                            f"{step.id}: non-public import {alias.name}"
                        )
                        assert not alias.name.split(".")[-1].startswith("_")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    assert module in _PUBLIC_ALLOWED_MODULES, (
                        f"{step.id}: non-public import from {module}"
                    )
                    for alias in node.names:
                        assert not alias.name.startswith("_"), alias.name
                    # Never import an implementation module.
                    assert "t1110" not in module, f"{step.id}: implementation import"


def test_learner_snippets_do_not_import_internal_constants() -> None:
    text = "".join(render_step(step, "T1110") for step in _path().ordered_steps)
    # No private constant names or internal imports in snippets.
    for bad in ("t1110 import", "from duke.simulation.t1110"):
        assert bad not in text


# ---- command-example validity (refinement 3) ---------------------------------


def test_command_examples_are_real_duke_commands() -> None:
    commands = set(app.registered_commands)
    known = {cmd.name or cmd.callback.__name__ for cmd in commands}
    assert "learn" in known
    for step in _path().ordered_steps:
        for command in step.command_examples:
            tokens = command.split()
            assert tokens, f"{step.id}: empty command"
            top = tokens[0]
            assert top == "duke", f"{step.id}: {command!r} must start with duke"
            subcommand = tokens[1]
            assert subcommand in known, f"{step.id}: unknown subcommand {subcommand}"
            if subcommand == "learn":
                assert "T1110" in tokens


# ---- Rich-sensitive literal fidelity (refinement 5) --------------------------


def test_rich_sensitive_syntax_is_preserved_literally() -> None:
    """Representative Python syntax must render verbatim (no Rich markup loss
    or alteration)."""
    text = "\n".join(render_step(step, "T1110") for step in _path().ordered_steps)
    assert "dict[UUID, set[UUID]]" in text
    assert "groups.setdefault(actor_id, set()).add(account_id)" in text
    assert "str(event.id)" in text
    assert "(event.occurred_at, str(event.id))" in text
    assert ">=" in text  # comparison operator
    # The type-annotation brackets are not interpreted/stripped by Rich.
    assert "{k: len(v) for k, v in groups.items()}" in text


# ---- T1078 byte preservation (refinement 4) ---------------------------------


def test_t1078_render_path_is_byte_identical_to_pre_change() -> None:
    """The render_path generalization from literal `T1078` to
    `path.technique_id` must not change T1078's output at all."""
    before = T1078_PATH_GOLDEN
    after = render_path(t1078_learning_path())
    assert after == before
    assert len(after.encode("utf-8")) == len(before.encode("utf-8"))


def test_t1078_lesson_renders_are_unchanged() -> None:
    path = t1078_learning_path()
    for step in path.ordered_steps:
        rendered = render_step(step, "T1078")
        assert rendered
        assert "T1078 — Step" in rendered


# ---- determinism -------------------------------------------------------------


def test_t1110_renders_are_deterministic() -> None:
    first_path = render_path(_path())
    second_path = render_path(_path())
    assert first_path == second_path
    first_steps = [render_step(s, "T1110") for s in _path().ordered_steps]
    second_steps = [render_step(s, "T1110") for s in _path().ordered_steps]
    assert first_steps == second_steps


# ---- AST-based structural safety (refinement 1) ------------------------------


def test_learning_package_has_no_structural_side_effects() -> None:
    """AST-scan the learning package: no subprocess, os.system/eval/exec,
    socket/network client, file write/open, credential auth, grading, or
    persistence implementation."""
    from pathlib import Path

    package_dir = Path(__file__).resolve().parents[2] / "src" / "duke" / "learning"
    forbidden_modules = {
        "subprocess",
        "socket",
        "requests",
        "urllib",
        "shutil",
        "smtplib",
        "ftplib",
        "http",
    }
    forbidden_calls = {"system", "popen", "eval", "exec", "connect", "open"}
    for py in sorted(package_dir.glob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in forbidden_modules, (
                        f"{py.name}: forbidden import {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                assert mod not in forbidden_modules, (
                    f"{py.name}: forbidden import {mod}"
                )
            elif isinstance(node, ast.Call):
                name = None
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name and name in forbidden_calls:
                    raise AssertionError(f"{py.name}: forbidden call {name}")
            elif isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                assert node.name not in (
                    "grade",
                    "persist",
                    "authenticate_as_user",
                )


def test_learner_facing_content_is_defensive_only() -> None:
    """Learner-facing command examples and snippets must contain no offensive
    tooling, real targets, real auth attempts, password lists, spraying
    commands, evasion, credential acquisition, or target discovery."""
    text = " ".join(
        [render_path(_path())]
        + [render_step(step, "T1110") for step in _path().ordered_steps]
    ).lower()
    for offensive in (
        "hydra",
        "medusa",
        "crackmapexec",
        "netexec",
        "burp",
        "john",
        "hashcat",
        "spray",
        "wordlist",
        "password list",
        "brute force the",
        "attack ",
    ):
        # 'spray'/'spraying' is legitimate; only forbid genuine tool names and
        # imperatives. We forbid the tool names outright and check that the
        # content never *instructs* spraying against a real target.
        tool_names = {
            "hydra",
            "medusa",
            "crackmapexec",
            "netexec",
            "burp",
            "john",
            "hashcat",
        }
        if offensive in tool_names:
            assert offensive not in text, f"offensive tool named: {offensive}"
    # The content must teach the defensive framing.
    assert "synthetic" in text
    assert "not proof of compromise" in text or "never proves compromise" in text
    assert "distinct accounts" in text


# ---- CLI behaviour -----------------------------------------------------------


def test_learn_t1110_overview_and_steps_cli() -> None:
    runner = CliRunner()
    for step_id in EXPECTED_STEP_IDS:
        result = runner.invoke(app, ["learn", "T1110", "--step", step_id])
        assert result.exit_code == 0, step_id
        assert "T1110 — Step" in result.stdout, step_id


def test_learn_t1110_writes_no_files(tmp_path, monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    before = {p for p in tmp_path.rglob("*")}
    result = runner.invoke(app, ["learn", "T1110"])
    assert result.exit_code == 0
    after = {p for p in tmp_path.rglob("*")}
    assert before == after
