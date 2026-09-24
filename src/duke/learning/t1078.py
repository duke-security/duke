"""The deterministic T1078 guided learning path.

This module defines the ordered catalogue of guided steps that walk a
beginner through Duke's completed T1078 workflow — simulation, detection,
investigation, response, validation, and reporting — while teaching Python
through defensive security engineering. It is pure, static metadata: it
never executes a command, never writes or modifies a file, never grades a
learner, and never persists progress.

All code snippets and command examples use documented public package
exports and real CLI syntax, never private helpers or internal constants.
"""

from duke.learning.models import (
    Exercise,
    Hint,
    KnowledgeCheck,
    LearningObjective,
    LearningPath,
    LearningStep,
)


def _step(
    step_id: str,
    ordinal: int,
    title: str,
    objective: str,
    concepts: tuple[str, ...],
    explanation: str,
    commands: tuple[str, ...],
    exercise_title: str,
    instructions: str,
    expected: str,
    hints: tuple[str, ...],
    check_prompt: str,
    check_answer: str,
    safety: str,
) -> LearningStep:
    """Build one deterministic learning step from plain strings."""
    return LearningStep(
        id=step_id,
        ordinal=ordinal,
        title=title,
        objective=LearningObjective(statement=objective),
        python_concepts=concepts,
        explanation=explanation,
        command_examples=commands,
        exercise=Exercise(
            title=exercise_title,
            instructions=instructions,
            expected_result=expected,
            hints=tuple(Hint(text=text) for text in hints),
            knowledge_check=KnowledgeCheck(prompt=check_prompt, answer=check_answer),
        ),
        safety_note=safety,
    )


_ARTEFACT_STRUCTURE = (
    "The T1078 artefact (data/events/t1078-session-001.json) is a "
    "TelemetryArtefact with a tuple of `entities` and a tuple of `events`. "
    "Each event carries an `action`, an `occurred_at` timestamp, and an "
    "`attributes` dictionary."
)


def _t1078_path() -> LearningPath:
    """Assemble the complete, ordered T1078 guided learning path."""
    steps = (
        _step(
            "orientation",
            1,
            "Orientation and safety",
            "Understand the T1078 valid-account scenario and its safety "
            "boundaries before using any model or command.",
            ("reading a scenario", "command-line usage", "synthetic data"),
            "Duke teaches Python through MITRE ATT&CK T1078 (Valid "
            "Accounts). The workflow is continuous and defensive: simulate, "
            "detect, investigate, respond, validate, and report. Every step "
            "uses synthetic entities and events in an isolated lab; nothing "
            "touches a real account, session, file, network, or security "
            "control. All Duke commands are dry-run and proposal-only.\n\n"
            + _ARTEFACT_STRUCTURE
            + "\n\nThroughout the path you will run two kinds of thing: real "
            "Duke CLI commands (shown as `$ ...` lines) and short Python "
            "snippets you can paste into a local interpreter against the "
            "same synthetic artefact.",
            (
                "duke learn T1078",
                "duke learn T1078 --step detection",
                "duke simulate T1078",
            ),
            "Inspect the synthetic artefact",
            "Run `duke simulate T1078` to (re)produce data/events/"
            "t1078-session-001.json, then open the file and identify its top "
            "three keys.",
            "schema_version = 1.0 with entities and events; 8 entities and "
            "8 events.",
            (
                "Use `duke simulate --help` to see the output path and the "
                "--force overwrite flag.",
                "The JSON is the same shape Duke's loader parses, so it is "
                "the single source of truth for later steps.",
            ),
            "Why is Duke's telemetry synthetic rather than collected from a "
            "real environment?",
            "The lab uses disposable, deterministic synthetic data so the "
            "scenario can be replayed safely without affecting any real "
            "system.",
            "Run only Duke's own commands and notebooks; no real account, "
            "session, network, or security control is accessed or modified.",
        ),
        _step(
            "collections",
            2,
            "Python collections",
            "Use lists and dictionaries to inspect the entities and events "
            "of a telemetry artefact.",
            ("lists", "dictionaries", "iteration", "attribute access"),
            "Events describe what was observed; their `action` strings and "
            "`attributes` dictionaries are ordinary Python data. Collections "
            "let you summarise a whole artefact without reading every row.\n\n"
            "```python\n"
            "from pathlib import Path\n"
            "from duke.telemetry import load_telemetry_artefact\n"
            "\n"
            "artefact = load_telemetry_artefact(\n"
            "    Path(\"data/events/t1078-session-001.json\")\n"
            ")\n"
            "counts: dict[str, int] = {}\n"
            "for event in artefact.events:\n"
            "    action = event.action\n"
            "    counts[action] = counts.get(action, 0) + 1\n"
            "print(counts)\n"
            "```",
            ("duke simulate T1078", "duke detect T1078 --input "
             "data/events/t1078-session-001.json"),
            "Summarise event actions into a dictionary",
            "Build a `dict` mapping each event `action` to how many times it "
            "occurs, and print the result.",
            "A dictionary counts distinct actions, for example "
            "`authenticate`, `access_application`, `enumerate_repository`, "
            "`read_file`, `request_privileged_access`, `create_archive`, and "
            "`network_connect`; `authenticate` appears twice.",
            (
                "Start with an empty `{}` and grow it with the "
                "`dict.get(key, 0)` pattern.",
                "Every event has an `action` attribute you can read directly.",
            ),
            "What does `counts.get(action, 0)` return when its key is "
            "missing?",
            "It returns the default 0 instead of raising, letting you "
            "increment a new counter safely.",
            "This only reads synthetic events; nothing is modified.",
        ),
        _step(
            "typed-models",
            3,
            "Typed models and validation",
            "Use Pydantic-validated Entity and SecurityEvent models and "
            "trust their guarantees.",
            ("Pydantic models", "typed fields", "validation", "immutability"),
            "Duke's core domain models are `DukeModel` (Pydantic) instances. "
            "Each field has a declared type, unknown fields are rejected "
            "(`extra='forbid'`), and timestamps must be timezone-aware. That "
            "means a malformed record fails fast at load instead of silently "
            "propagating.\n\n"
            "```python\n"
            "user = next(\n"
            "    e for e in artefact.entities\n"
            "    if e.identifier == \"alex.morgan@example.lab\"\n"
            ")\n"
            "print(user.entity_type, user.display_name)\n"
            "print(type(user), user.model_dump()[\"entity_type\"])\n"
            "```",
            ("duke detect T1078 --input data/events/t1078-session-001.json",),
            "Inspect a typed Entity",
            "Locate the `Entity` for the account and print its `entity_type` "
            "and `display_name`.",
            "`account` and `Alex Morgan`, printed from typed attributes.",
            (
                "Use a list comprehension with `next(...)` to find one entity.",
                "Entities expose `entity_type` and `display_name` fields.",
            ),
            "What happens if you feed a record with an unexpected field to an "
            "Entity?",
            "`extra='forbid'` validation rejects it with a ValidationError "
            "instead of silently dropping the data.",
            "You are only reading a synthetic Entity; no change is made.",
        ),
        _step(
            "datetime",
            4,
            "Datetime arithmetic and the correlation window",
            "Do datetime arithmetic against the detection rule's 15-minute "
            "correlation window.",
            ("datetime", "timedelta", "aware datetimes", "comparison"),
            "Every event records `occurred_at` as a timezone-aware UTC "
            "datetime. Detection correlates a new-context login with distinct "
            "follow-on behaviours inside a 15-minute window; doing that "
            "arithmetic yourself is pure `timedelta` work.\n\n"
            "```python\n"
            "from datetime import timedelta\n"
            "\n"
            "window = timedelta(minutes=15)  # documented correlation window\n"
            "login = next(\n"
            "    e for e in artefact.events\n"
            "    if e.attributes.get(\"network_context\") == \"new\"\n"
            ")\n"
            "within = [\n"
            "    e for e in artefact.events\n"
            "    if login.occurred_at < e.occurred_at\n"
            "    and e.occurred_at <= login.occurred_at + window\n"
            "]\n"
            "print(len(within))\n"
            "```",
            ("duke detect T1078 --input data/events/t1078-session-001.json",),
            "Select follow-on events inside the window",
            "Find the new-context login, then list the events that occur "
            "after it but within 15 minutes, and print the count.",
            "The follow-on behaviours inside the window number 5 (distinct "
            "from the baseline and later-less-relevant events).",
            (
                "Remember `strictly after` the login (use `<`, not `<=`).",
                "The window upper bound is inclusive, so use `<=` on the "
                "right side.",
            ),
            "Why must `occurred_at` be timezone-aware rather than naive?",
            "Aware datetimes make interval arithmetic consistent and "
            "unambiguous across UTC, so comparisons are always valid.",
            "This only reads timestamps from synthetic data; nothing runs.",
        ),
        _step(
            "functions-modules",
            5,
            "Functions and modules",
            "Compose Duke's simulation and detection functions across "
            "modules.",
            ("functions", "modules", "imports", "return values", "tuples"),
            "Duke is organised into modules that each own one job. The "
            "simulation module generates a deterministic `SimulationResult`; "
            "the detection module consumes a sequence of events and returns "
            "a tuple of `Finding` objects. Import the public entry points and "
            "pass data between them.\n\n"
            "```python\n"
            "from duke.simulation import generate_t1078_simulation\n"
            "from duke.detection import detect_t1078\n"
            "\n"
            "result = generate_t1078_simulation()\n"
            "findings = detect_t1078(result.events)\n"
            "print(len(findings), findings[0].confidence)\n"
            "```",
            (
                "duke simulate T1078",
                "duke detect T1078 --input data/events/t1078-session-001.json",
            ),
            "Chain simulation into detection",
            "Generate a simulation in memory and pass its events to "
            "`detect_t1078`, then print the number of findings and the first "
            "finding's confidence.",
            "1 finding at confidence 90, showing the two modules compose "
            "cleanly through their public functions.",
            (
                "`detect_t1078` expects the events sequence, not the whole "
                "result object.",
                "`SimulationResult` exposes `.events` (and `.entities`).",
            ),
            "What does `detect_t1078` return?",
            "A tuple of `Finding` objects (possibly empty) — Python's "
            "immutable sequence type.",
            "Both functions operate only on in-memory synthetic data.",
        ),
        _step(
            "detection",
            6,
            "Detection reasoning",
            "Reason about weighted confidence and the documented detection "
            "threshold.",
            ("confidence scoring", "thresholds", "conditionals"),
            "The `compromised-identity-sequence` rule infers risk from "
            "behaviour and context, not from labelled events. It requires a "
            "known-good baseline, anchors on a new-context login, and adds "
            "weighted points for distinct follow-on behaviours. A `Finding` "
            "is emitted when the weighted score reaches the documented "
            "threshold of 60/100. You can read the resulting confidence from "
            "the `Finding`; you do **not** need to import any internal "
            "constant to reason about it.\n\n"
            "```python\n"
            "for finding in detect_t1078(artefact.events):\n"
            "    confident = finding.confidence >= 60  # documented threshold\n"
            "    print(finding.confidence, finding.severity, confident)\n"
            "```",
            ("duke detect T1078 --input data/events/t1078-session-001.json",),
            "Inspect a finding's confidence",
            "Run detection and, for each finding, check whether its "
            "confidence meets the documented threshold of 60 and print it "
            "together with the severity.",
            "One finding at confidence 90 (above 60) with severity high, "
            "printed as `90 high True`.",
            (
                "Each `Finding` has a `.confidence` integer from 0 to 100.",
                "Severity is derived from confidence but never asserts a "
                "confirmed compromise.",
            ),
            "At what documented confidence does a Finding first appear?",
            "60/100 — a new-context login alone (25 points) stays below it "
            "and produces nothing.",
            "Detection only reads events and returns a finding; no action "
            "is taken or executed.",
        ),
        _step(
            "investigation",
            7,
            "Evidence-led investigation",
            "Trace a finding to its evidence using IDs, relationships, and "
            "chronological sorting.",
            ("sorting", "key functions", "UUIDs", "relationships"),
            "Investigation turns a finding into an `InvestigationResult` "
            "with an `Evidence` register (each piece has an ID, a "
            "`source_event_id`, and a `relationship`) and a `timeline` of "
            "`TimelineEntry` records. Sorting by `occurred_at` with a `key` "
            "function is exactly how an analyst rebuilds the order of "
            "events.\n\n"
            "```python\n"
            "result = investigate_t1078(artefact, finding)\n"
            "for entry in sorted(result.timeline, key=lambda e: e.occurred_at):\n"
            "    print(entry.occurred_at.isoformat(), entry.event_id, entry.summary)\n"
            "```",
            ("duke investigate T1078 --input data/events/t1078-session-001.json",),
            "Print the timeline in chronological order",
            "Investigate the finding, sort its timeline by `occurred_at`, "
            "and print the timestamp, event ID, and summary of each entry.",
            "Timeline entries printed oldest-to-newest, each with a UTC "
            "timestamp, the exact `SecurityEvent` ID, and a human summary.",
            (
                "Use `key=lambda entry: entry.occurred_at` as the sort key.",
                "Each `TimelineEntry` exposes `.occurred_at`, `.event_id`, and "
                "`.summary`.",
            ),
            "What does an Evidence `relationship` of 'supports' mean here?",
            "'supports' means the piece of evidence corroborates the finding; "
            "'provides_context' (the baseline) frames but does not implicate.",
            "Investigation only organises the revealing of existing synthetic "
            "evidence.",
        ),
        _step(
            "response",
            8,
            "Safe response planning",
            "Interpret safe response plans: enums, approval flags, dry-run "
            "state, and rollback.",
            ("StrEnum", "boolean flags", "attributes"),
            "Response planning is proposal-only. `plan_t1078_response` "
            "returns a `ResponsePlan` whose actions are grouped by "
            "`ResponseCategory`; every action is `dry_run=True`, "
            "`requires_approval=True`, and `status=PLANNED`, and "
            "`supports_rollback` decides whether rollback guidance exists. "
            "Reading these attributes is how you confirm nothing executes "
            "automatically.\n\n"
            "```python\n"
            "plan = plan_t1078_response(artefact, result)\n"
            "for action in plan.actions():\n"
            "    print(action.name, action.dry_run,\n"
            "          action.requires_approval, action.status)\n"
            "```",
            ("duke respond T1078 --input data/events/t1078-session-001.json",),
            "Inspect a proposed response plan",
            "Build the response plan and print each action's name, dry-run "
            "flag, approval requirement, and status.",
            "Nine actions, each printed with `True True planned` — every one "
            "dry-run, approval-required, and planned, never executed.",
            (
                "Use `plan.actions()` to flatten the grouped actions.",
                "`dry_run`, `requires_approval`, and `status` are plain "
                "attributes on each action.",
            ),
            "Why is every action dry-run and approval-gated?",
            "Duke never modifies a real system: nothing executes without "
            "explicit human approval, so response is always a proposal.",
            "Response remains a dry-run recommendation; no action is executed.",
        ),
        _step(
            "validation",
            9,
            "Detection validation",
            "Use controlled in-memory mutations and deterministic checks to "
            "validate detection.",
            ("immutability", "model_copy", "deterministic tests", "booleans"),
            "Validation proves detection keeps behaving correctly. "
            "`validate_t1078` makes immutable, in-memory copies of the "
            "artefact (never modifying the source), applies controlled "
            "mutations, and reports a `ValidationSuiteResult` whose "
            "`all_passed` flag is derived from every case. It is fully "
            "deterministic and side-effect-free.\n\n"
            "```python\n"
            "suite = validate_t1078(artefact)\n"
            "print(suite.all_passed, len(suite.cases))\n"
            "```",
            ("duke validate T1078 --input data/events/t1078-session-001.json",),
            "Check validation all_passed",
            "Validate the artefact and print whether the whole suite passed "
            "and how many cases it contains.",
            "`True 16`: all 16 explicit validation cases pass deterministically.",
            (
                "`validate_t1078` returns a `ValidationSuiteResult`.",
                "`.all_passed` is True exactly when every case has PASS status.",
            ),
            "How does validation avoid changing the source artefact?",
            "It copies models in memory (immutable tuples and `model_copy`) "
            "and never writes files, so the input is untouched.",
            "Validation is read-only: the source artefact and files are "
            "unchanged.",
        ),
        _step(
            "reporting",
            10,
            "Reporting",
            "Turn structured workflow data into deterministic Markdown.",
            ("structured data", "deterministic rendering", "strings"),
            "`report_t1078` aggregates the finding, investigation, response "
            "plan, and validation suite into an `IncidentReport`, and "
            "`render_incident_report` turns it into byte-deterministic "
            "Markdown. Because the report timestamp is derived from the "
            "finding rather than wall-clock time, the same input always "
            "renders identically.\n\n"
            "```python\n"
            "from duke.reporting import report_t1078, render_incident_report\n"
            "\n"
            "report = report_t1078(artefact, finding, result, plan, suite)\n"
            "markdown = render_incident_report(report)\n"
            "print(markdown[:120])\n"
            "```",
            ("duke report T1078 --input data/events/t1078-session-001.json "
             "--output reports/t1078-incident-report.md",),
            "Render a report in memory",
            "Build the `IncidentReport` and render its Markdown, printing "
            "the first 120 characters.",
            "Output begins `# T1078 Incident Report`, a deterministic "
            "heading that is the same on every run.",
            (
                "`report_t1078` needs the artefact, finding, result, plan, "
                "and suite.",
                "`render_incident_report` is a pure function of its input.",
            ),
            "Why is the report's generated timestamp not the wall-clock "
            "time?",
            "It is derived from the detection timestamp so the report is "
            "fully reproducible from the artefact.",
            "Reporting is advisory and reads only synthetic workflow data.",
        ),
        _step(
            "final-challenge",
            11,
            "Final challenge: the full learning loop",
            "Run Duke's complete T1078 loop end to end and explain each "
            "stage.",
            ("pipelines", "function composition", "verification"),
            "Now connect every implemented stage. Work through the real CLI "
            "commands in order, confirm the expected result at each step, and "
            "weave the Python concepts you have just practised into a short "
            "explanation of what each stage observes. This challenge only "
            "instructs you — Duke will not run the commands, grade your "
            "explanation, modify any file, or remember your progress.\n\n"
            "```bash\n"
            "duke simulate T1078\n"
            "duke detect T1078 --input data/events/t1078-session-001.json\n"
            "duke investigate T1078 --input data/events/t1078-session-001.json\n"
            "duke respond T1078 --input data/events/t1078-session-001.json\n"
            "duke validate T1078 --input data/events/t1078-session-001.json\n"
            "duke report T1078 --input data/events/t1078-session-001.json \\\n"
            "  --output reports/t1078-incident-report.md\n"
            "```",
            (
                "duke simulate T1078",
                "duke detect T1078 --input data/events/t1078-session-001.json",
                "duke investigate T1078 --input "
                "data/events/t1078-session-001.json",
                "duke respond T1078 --input "
                "data/events/t1078-session-001.json",
                "duke validate T1078 --input "
                "data/events/t1078-session-001.json",
                "duke report T1078 --input data/events/t1078-session-001.json "
                "--output reports/t1078-incident-report.md",
            ),
            "Run and explain the full loop",
            "Execute the six commands in order. For each, confirm the "
            "expected outcome, then write one sentence naming the Duke "
            "component responsible and the Python concept it exercised.",
            "Each command succeeds in order: 8 entities/8 events simulated, 1 "
            "finding at confidence 90, an evidence-led investigation, a 9-"
            "action dry-run plan, 16/16 validation cases passing, and a "
            "written advisory report.",
            (
                "Reset any existing report with `--force` if you re-run "
                "report.",
                "If validation ever fails, stop: detection is mis-behaving and "
                "no report should be produced.",
                "Refer back to a step's command example if a command's flags "
                "look unfamiliar.",
            ),
            "Which Duke component runs at each of the six commands?",
            "simulation → detection → investigation → response → validation "
            "→ reporting, mapping one-to-one onto the pipeline and the "
            "corresponding documentation.",
            "The challenge is instructional only: nothing executes, modifies, "
            "grades, or persists automatically.",
        ),
    )

    return LearningPath(
        technique_id="T1078",
        title="T1078 Guided Learning Path",
        description=(
            "A beginner-friendly, deterministic path that teaches Python "
            "through Duke's defensive T1078 workflow, from safe simulation "
            "through deterministic reporting."
        ),
        steps=steps,
    )


T1078_LEARNING_PATH = _t1078_path()
"""The deterministic T1078 learning path (built once at import time)."""


def t1078_learning_path() -> LearningPath:
    """Return the deterministic T1078 guided learning path.

    The path is immutable and built once at import time, so callers can
    rely on byte-for-byte identical content across runs.
    """
    return T1078_LEARNING_PATH


__all__ = ["T1078_LEARNING_PATH", "t1078_learning_path"]
