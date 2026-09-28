"""The deterministic T1110 guided learning path.

This module defines the ordered catalogue of guided steps that walk a learner
through Duke's completed T1110 workflow — simulation, detection,
investigation, response, validation, and reporting — while teaching Python
through defensive security engineering of the Password Spraying sub-technique
(T1110.003) of MITRE ATT&CK Brute Force (T1110).

It is pure, static metadata: it never executes a command, never writes or
modifies a file, never grades a learner, and never persists progress. All code
snippets use documented public package exports (never private helpers or the
`duke.*.t1110` implementation modules) and real CLI syntax. Content is
strictly defensive: it never teaches password spraying, credential
acquisition, evasion, target discovery, or any offensive tool, and it always
distinguishes Duke's synthetic simulation from a real authentication attempt.
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
    "The T1110 artefact (data/events/t1110-session-001.json) is a "
    "TelemetryArtefact with a tuple of `entities` (10) and a tuple of `events` "
    "(8). Each event carries an `action`, an `occurred_at` timestamp, an "
    "`outcome` (success or failure), and an `attributes` dictionary."
)

# Public-import snippet used across steps; kept literal and Rich-safe.
_GROUPING_SNIPPET = (
    "```python\n"
    "from pathlib import Path\n"
    "from uuid import UUID\n"
    "from duke.telemetry import load_telemetry_artefact\n"
    "\n"
    "artefact = load_telemetry_artefact(\n"
    "    Path(\"data/events/t1110-session-001.json\")\n"
    ")\n"
    "groups: dict[UUID, set[UUID]] = {}\n"
    "for event in artefact.events:\n"
    "    actor_id = event.actor_entity_id\n"
    "    for account_id in event.target_entity_ids:\n"
    "        groups.setdefault(actor_id, set()).add(account_id)\n"
    "print({k: len(v) for k, v in groups.items()})\n"
    "```"
)


def _t1110_path() -> LearningPath:
    """Assemble the complete, ordered T1110 guided learning path."""
    steps = (
        _step(
            "orientation",
            1,
            "Orientation and safety",
            "Understand the T1110 Password Spraying scenario, its technique "
            "and sub-technique identifiers, and its safety boundaries before "
            "using any model or command.",
            ("reading a scenario", "command-line usage", "synthetic data"),
            "Duke teaches Python through cyber-defence. This path studies "
            "MITRE ATT&CK T1110 (Brute Force), specifically the Password "
            "Spraying sub-technique T1110.003: many *failed* authentications "
            "against distinct accounts from one source inside a bounded "
            "window. The registered canonical technique ID is `T1110`, and "
            "the defensive behaviour under study is `T1110.003`.\n\n"
            "The canonical T1110 corpus is 10 entities and 8 events, detected "
            "as 1 finding at confidence 80 (severity high) with 7 supporting "
            "events, 7 investigation evidence items, a 9-action response "
            "plan, a 19-case validation suite (19/19 passing), and a "
            "12-section report. These exact numbers are the expected results "
            "you will confirm in later steps.\n\n"
            "Everything uses synthetic entities and events in an isolated "
            "lab; Duke simulates the *observable telemetry* of the pattern, "
            "never a real authentication attempt. Nothing touches a real "
            "account, credential, service, network, or security control.\n\n"
            + _ARTEFACT_STRUCTURE
            + "\n\nThroughout the path you will run real Duke CLI commands "
            "(shown as `$ ...` lines) and short Python snippets you can paste "
            "into a local interpreter against the same synthetic artefact. "
            "Duke never executes your snippets for you.",
            (
                "duke learn T1110",
                "duke learn T1110 --step detection",
                "duke simulate T1110 --output data/events/t1110-session-001.json",
            ),
            "Inspect the synthetic artefact",
            "Run `duke simulate T1110` (with the explicit output path) to "
            "produce data/events/t1110-session-001.json, then open the file "
            "and identify its top three keys and the entity/event counts.",
            "schema_version = 1.0 with entities and events; 10 entities and "
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
            "system; it is an education aid, not real authentication.",
            "Run only Duke's own commands; no real account, credential, "
            "session, network, or security control is accessed or modified.",
        ),
        _step(
            "collections",
            2,
            "Python collections",
            "Group authentication events by source actor and count distinct "
            "target accounts using lists, dictionaries, and sets.",
            ("lists", "dictionaries", "sets", "iteration", "dict.setdefault"),
            "Events describe what was observed. Spray events carry the acting "
            "source as `actor_entity_id` and the attempted account as a "
            "target. Grouping failure events by source and tracking the "
            "*set* of distinct target accounts is the core of the spray "
            "pattern.\n\n"
            + _GROUPING_SNIPPET,
            (
                "duke simulate T1110 --output data/events/t1110-session-001.json",
                "duke detect T1110 --input data/events/t1110-session-001.json",
            ),
            "Group by source and count distinct accounts",
            "Load the artefact, group failed authentications by source actor, "
            "and print the number of distinct target accounts per source "
            "using a set.",
            "The source appears once with 6 distinct accounts; "
            "`dict.setdefault(actor_id, set())` grows a fresh set on first use "
            "so each account is added exactly once.",
            (
                "Use `groups.setdefault(actor_id, set()).add(account_id)` so "
                "missing sources start with an empty set.",
                "A `set` holds distinct values, so re-adding an account is a "
                "no-op.",
            ),
            "Why must we use a `set` for the distinct accounts rather than a "
            "list?",
            "A set stores only unique values, so a repeated failure against "
            "the same account still counts it once.",
            "This only reads synthetic events; nothing is modified.",
        ),
        _step(
            "typed-models",
            3,
            "Typed models and validation",
            "Use Pydantic-validated Entity, SecurityEvent, and Finding models "
            "and trust their guarantees.",
            ("Pydantic models", "typed fields", "validation", "immutability"),
            "Duke's core domain models are `DukeModel` (Pydantic) instances. "
            "Each field has a declared type, unknown fields are rejected "
            "(`extra='forbid'`), and timestamps must be timezone-aware. An "
            "`Entity` has an `entity_type`; a `SecurityEvent` has an "
            "`outcome` (success or failure) and actor/target IDs. A `Finding` "
            "is an *analytic signal*, not proof of compromise.\n\n"
            "```python\n"
            "source = next(\n"
            "    e for e in artefact.entities\n"
            "    if e.identifier == \"host-198.51.100.77\"\n"
            ")\n"
            "print(source.entity_type.value, source.identifier)\n"
            "```",
            ("duke detect T1110 --input data/events/t1110-session-001.json",),
            "Inspect a typed Entity",
            "Locate the source `Entity` and print its `entity_type` and "
            "`identifier`.",
            "`host` and `host-198.51.100.77`, printed from typed attributes.",
            (
                "Entities expose `entity_type` and `identifier` fields.",
                "The source host is an `EntityType.HOST` in the synthetic data.",
            ),
            "What happens if you feed a record with an unexpected field to "
            "an `Entity`?",
            "`extra='forbid'` validation rejects it with a ValidationError "
            "instead of silently dropping the data.",
            "You are only reading synthetic Entities; no change is made.",
        ),
        _step(
            "datetime",
            4,
            "The sliding 30-minute window",
            "Reason about correlations bounded by a fixed 30-minute window "
            "and deterministic timestamp ordering.",
            ("datetime", "timedelta", "aware datetimes", "sorting"),
            "Detection evaluates sliding 30-minute windows that begin at each "
            "failed authentication. A window qualifies only when it holds at "
            "least five distinct accounts; contributing failures are bounded "
            "by the window, and ties are broken by the earliest window start "
            "and then event ID. You can reproduce the time-bound reasoning "
            "with `timedelta` yourself.\n\n"
            "```python\n"
            "from datetime import timedelta\n"
            "\n"
            "window = timedelta(minutes=30)  # documented correlation window\n"
            "ordered = sorted(\n"
            "    artefact.events,\n"
            "    key=lambda event: (event.occurred_at, str(event.id)),\n"
            ")\n"
            "window_end = ordered[0].occurred_at + window\n"
            "in_window = [\n"
            "    e for e in ordered\n"
            "    if ordered[0].occurred_at <= e.occurred_at <= window_end\n"
            "]\n"
            "print(f\"{len(in_window)} events inside the window\")\n"
            "```",
            ("duke detect T1110 --input data/events/t1110-session-001.json",),
            "Select events inside the window",
            "Sort events by `(occurred_at, str(id))` and count those within "
            "30 minutes of the earliest event.",
            "All 8 events fall within a 30-minute span, printed via an f-string.",
            (
                "Sort with a tuple key `(occurred_at, str(id))` for "
                "determinism.",
                "The window upper bound is inclusive, so use `<=` on the right.",
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
            "Compose Duke's simulation and registry-dispatched lifecycle "
            "functions across modules.",
            ("functions", "modules", "imports", "return values", "tuples"),
            "Duke is organised into modules that each own one job. The "
            "simulation module generates a deterministic `SimulationResult`; "
            "the detection module consumes events and returns a tuple of "
            "`Finding` objects. Import the public entry points and pass data "
            "between them — never import the internal implementation modules.\n\n"
            "```python\n"
            "from duke.simulation import generate_t1110_simulation\n"
            "from duke.detection import detect_t1110\n"
            "\n"
            "result = generate_t1110_simulation()\n"
            "findings = detect_t1110(result.events)\n"
            "print(len(findings), findings[0].confidence)\n"
            "```",
            (
                "duke simulate T1110 --output data/events/t1110-session-001.json",
                "duke detect T1110 --input data/events/t1110-session-001.json",
            ),
            "Chain simulation into detection",
            "Generate a simulation in memory, pass its events to "
            "`detect_t1110`, and print the number of findings and the first "
            "finding's confidence.",
            "1 finding at confidence 80, showing the two modules compose "
            "cleanly through their public functions.",
            (
                "`detect_t1110` expects the events sequence, not the whole result.",
                "`SimulationResult` exposes `.events` (and `.entities`).",
            ),
            "What does `detect_t1110` return?",
            "A tuple of `Finding` objects (possibly empty) — Python's "
            "immutable sequence type.",
            "Both functions operate only on in-memory synthetic data.",
        ),
        _step(
            "detection",
            6,
            "Detection reasoning",
            "Reason about the spray gate, set semantics, confidence, severity, "
            "and why a later success is supporting evidence only.",
            ("thresholds", "set semantics", "confidence", "severity"),
            "The `password-spraying-window` rule infers risk from observable "
            "behaviour, not from labelled events. A window qualifies only "
            "when at least **five distinct accounts** failed within the "
            "**30-minute** window; a shared authentication service never "
            "counts as an account, and repeated failures against one account "
            "do not inflate the count. Confidence starts at a floor of 60, "
            "gains 5 per account beyond the threshold (capped), and gains 15 "
            "only when a later success from the same source follows an "
            "account's failure inside the window. These are stated in prose — "
            "you never need to import an internal constant.\n\n"
            "```python\n"
            "findings = detect_t1110(artefact.events)\n"
            "for finding in findings:\n"
            "    meets_floor = finding.confidence >= 60  # documented floor\n"
            "    print(\n"
            "        finding.technique_id, finding.confidence,\n"
            "        finding.severity.value, meets_floor,\n"
            "    )\n"
            "```",
            ("duke detect T1110 --input data/events/t1110-session-001.json",),
            "Inspect a finding's confidence and severity",
            "Run detection and, for each finding, print its technique ID, "
            "confidence, severity, and whether it meets the documented floor "
            "of 60.",
            "`T1110 80 high True` — the canonical finding is confidence 80, "
            "severity high.",
            (
                "Each `Finding` has `.confidence`, `.severity`, and "
                "`.technique_id`.",
                "A later success raises confidence as supporting evidence but "
                "never proves compromise.",
            ),
            "Why is a later success treated only as supporting evidence?",
            "A success after many failures is consistent with a credential "
            "having validated, but it does not prove the account was "
            "compromised; impact and intent stay unresolved.",
            "Detection only reads events and returns a finding; no action is "
            "taken or executed.",
        ),
        _step(
            "investigation",
            7,
            "Evidence-led investigation",
            "Trace a T1110 finding to its referenced evidence, timeline, "
            "facts, assessments, and unresolved questions.",
            ("sorting", "UUIDs", "relationships", "evidence"),
            "Investigation consumes an existing finding — it never reruns "
            "detection and never scans the whole artefact for a new pattern. "
            "It gathers one `Evidence` per referenced event, a chronological "
            "`timeline`, and keeps `confirmed_facts`, `analyst_assessments`, "
            "and `unresolved_questions` distinct. Sorting by "
            "`(occurred_at, str(id))` preserves deterministic order.\n\n"
            "```python\n"
            "finding = detect_t1110(artefact.events)[0]\n"
            "result = investigate_t1110(artefact, finding)\n"
            "print(len(result.evidence), len(result.timeline))\n"
            "for entry in sorted(\n"
            "    result.timeline, key=lambda e: (e.occurred_at, str(e.event_id))\n"
            "):\n"
            "    print(entry.occurred_at.isoformat(), entry.summary)\n"
            "```",
            ("duke investigate T1110 --input data/events/t1110-session-001.json",),
            "Print the investigation evidence and timeline",
            "Investigate the finding, then print the evidence count and every "
            "timeline entry sorted chronologically.",
            "7 evidence items and 7 timeline entries, each printed oldest to "
            "newest by `occurred_at` then event ID.",
            (
                "`result.evidence` and `result.timeline` expose the collected data.",
                "Sort with a tuple key `(occurred_at, str(id))`.",
            ),
            "Why does investigation use only the finding's referenced events?",
            "It deliberately narrows to what the finding already selected so "
            "it stays evidence-led and does not pull in unrelated artefact data.",
            "Investigation only organises existing synthetic evidence; nothing "
            "is changed.",
        ),
        _step(
            "response",
            8,
            "Safe response planning",
            "Interpret dry-run response plans: approval gates, target "
            "ambiguity, risk, verification, and rollback.",
            ("StrEnum", "boolean flags", "attributes", "rollback"),
            "Response planning is proposal-only: `plan_t1110_response` "
            "returns a `ResponsePlan` whose actions are grouped by "
            "`ResponseCategory`. Every action is `dry_run=True`, "
            "`requires_approval=True`, and `status=PLANNED`. Targets are "
            "evidence-led — the source and sprayed accounts — and an "
            "ambiguous source or success account causes the related action to "
            "be omitted rather than guessed. Reversible actions carry rollback "
            "guidance; review-only actions carry none.\n\n"
            "```python\n"
            "plan = plan_t1110_response(artefact, result)\n"
            "for action in plan.actions():\n"
            "    print(\n"
            "        action.name, action.dry_run,\n"
            "        action.requires_approval,\n"
            "        action.status.value,\n"
            "    )\n"
            "```",
            ("duke respond T1110 --input data/events/t1110-session-001.json",),
            "Inspect a proposed response plan",
            "Build the response plan and print each action's name, dry-run "
            "flag, approval requirement, and status.",
            "Nine actions, each printed with `True True planned` — every one "
            "dry-run, approval-required, and planned, never executed.",
            (
                "Use `plan.actions()` to flatten grouped actions.",
                "`dry_run`, `requires_approval`, and `status` are plain "
                "attributes on each action.",
            ),
            "Why is every response action dry-run and approval-gated?",
            "Duke never modifies a real system: nothing executes without "
            "explicit human approval, so response is always a proposal.",
            "Response remains a dry-run recommendation; no action is executed.",
        ),
        _step(
            "validation",
            9,
            "Detection validation",
            "Use immutable in-memory mutations, the ordered 19-case suite, "
            "negative controls, and deterministic retesting.",
            ("immutability", "model_copy", "deterministic tests", "booleans"),
            "Validation proves detection keeps behaving correctly. "
            "`validate_t1110` builds immutable in-memory copies of the "
            "artefact (never modifying the source), applies controlled "
            "mutations including negative controls (e.g. only four distinct "
            "accounts), and returns a `ValidationSuiteResult` whose "
            "`all_passed` flag derives from every case. The ordered suite has "
            "**19 cases** and is fully deterministic.\n\n"
            "```python\n"
            "suite = validate_t1110(artefact)\n"
            "print(suite.all_passed, len(suite.cases))\n"
            "for case in suite.cases[:2]:\n"
            "    print(case.name, case.status.value)\n"
            "```",
            ("duke validate T1110 --input data/events/t1110-session-001.json",),
            "Check validation all_passed",
            "Validate the artefact and print whether the whole suite passed, "
            "how many cases it contains, and the first few case names/status.",
            "`True 19` — all 19 explicit validation cases pass "
            "deterministically; the first case is `suspicious-corpus-unmodified` "
            "(pass).",
            (
                "`validate_t1110` returns a `ValidationSuiteResult`.",
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
            "Turn structured workflow data into cautious, deterministic "
            "Markdown with 12 sections and escaping.",
            ("structured data", "deterministic rendering", "strings"),
            "`report_t1110` aggregates the finding, investigation, response "
            "plan, and validation suite into an `IncidentReport`, and "
            "`render_incident_report` turns it into byte-deterministic "
            "Markdown with 12 sections. Because the report timestamp derives "
            "from the finding rather than wall-clock time, the same input "
            "always renders identically, and table cells are escaped so pipes "
            "and line breaks cannot corrupt the structure.\n\n"
            "```python\n"
            "from duke.reporting import report_t1110, render_incident_report\n"
            "\n"
            "report = report_t1110(artefact, finding, result, plan, suite)\n"
            "markdown = render_incident_report(report)\n"
            "print(markdown[:120])\n"
            "```",
            (
                "duke report T1110 --input data/events/t1110-session-001.json "
                "--output reports/t1110-incident-report.md",
            ),
            "Render a report in memory",
            "Build the `IncidentReport` and render its Markdown, printing the "
            "first 120 characters.",
            "Output begins `# T1110 Incident Report`, a deterministic heading "
            "that is the same on every run.",
            (
                "`report_t1110` needs the artefact, finding, result, plan, and "
                "suite.",
                "`render_incident_report` is a pure function of its input.",
            ),
            "Why is the report's generated timestamp not the wall-clock time?",
            "It is derived from the detection timestamp so the report is fully "
            "reproducible from the artefact.",
            "Reporting is advisory and reads only synthetic workflow data; "
            "nothing is executed.",
        ),
        _step(
            "final-challenge",
            11,
            "Final challenge: the full defensive workflow",
            "Run Duke's complete T1110 loop end to end and explain each "
            "stage.",
            ("pipelines", "function composition", "verification"),
            "Now connect every implemented stage. Work through the real CLI "
            "commands in order, confirming the expected result at each step, "
            "and weave the Python concepts you have just practised into a "
            "short explanation of what each stage observes. This challenge "
            "only **instructs** you — Duke will not run the commands for you, "
            "grade your explanation, modify any file, or remember your "
            "progress.\n\n"
            "```bash\n"
            "duke simulate T1110 --output data/events/t1110-session-001.json\n"
            "duke detect T1110 --input data/events/t1110-session-001.json\n"
            "duke investigate T1110 --input data/events/t1110-session-001.json\n"
            "duke respond T1110 --input data/events/t1110-session-001.json\n"
            "duke validate T1110 --input data/events/t1110-session-001.json\n"
            "duke report T1110 --input data/events/t1110-session-001.json \\\n"
            "  --output reports/t1110-incident-report.md\n"
            "```",
            (
                "duke simulate T1110 --output data/events/t1110-session-001.json",
                "duke detect T1110 --input data/events/t1110-session-001.json",
                "duke investigate T1110 --input data/events/t1110-session-001.json",
                "duke respond T1110 --input data/events/t1110-session-001.json",
                "duke validate T1110 --input data/events/t1110-session-001.json",
                "duke report T1110 --input data/events/t1110-session-001.json "
                "--output reports/t1110-incident-report.md",
            ),
            "Run and explain the full loop",
            "Execute the six commands in order. For each, confirm the expected "
            "outcome, then write one sentence naming the Duke component "
            "responsible and the Python concept it exercised.",
            "Each command succeeds in order: simulate to an artefact path, 10 "
            "entities/8 events detected as 1 finding at confidence 80, an "
            "evidence-led investigation (7 evidence items), a 9-action dry-run "
            "plan, 19/19 validation cases passing, and a written advisory "
            "report with 12 sections.",
            (
                "Reset any existing report with `--force` if you re-run report.",
                "If validation ever fails, stop: detection is misbehaving and "
                "no report should be produced.",
                "Refer back to a step's command example if a command's flags "
                "look unfamiliar.",
            ),
            "Which Duke component runs at each of the six commands?",
            "simulation → detection → investigation → response → validation → "
            "reporting, mapping one-to-one onto the pipeline and the "
            "corresponding documentation.",
            "The challenge is instructional only: nothing executes, modifies, "
            "grades, or persists automatically.",
        ),
    )

    return LearningPath(
        technique_id="T1110",
        title="T1110 Guided Learning Path",
        description=(
            "A beginner-friendly, deterministic path that teaches Python "
            "through Duke's defensive T1110.003 Password Spraying workflow, "
            "from safe simulation through deterministic reporting, always on "
            "synthetic data."
        ),
        steps=steps,
    )


T1110_LEARNING_PATH = _t1110_path()
"""The deterministic T1110 learning path (built once at import time)."""


def t1110_learning_path() -> LearningPath:
    """Return the deterministic T1110 guided learning path.

    The path is immutable and built once at import time, so callers can rely
    on byte-for-byte identical content across runs.
    """
    return T1110_LEARNING_PATH


__all__ = ["T1110_LEARNING_PATH", "t1110_learning_path"]
