# T1078 Guided Learning Path

## Status

A T1078 guided learning path is implemented: an 11-step, beginner-friendly,
deterministic walk that teaches Python through Duke's defensive T1078
workflow. It is a guided *learning* path for the already-implemented
workflow; it is not the entire learning component. Remaining learning work
is listed under [Planned](#planned).

## Purpose

`duke learn T1078` turns the completed end-to-end T1078 workflow — safe
simulation, normalized telemetry, detection, investigation, response,
validation, and reporting — into an ordered set of lessons that teach Python
while reinforcing defensive security reasoning. Each step reuses the real
Duke CLI commands and public Python exports, so what a learner reads is
exactly what they can run.

The learning path is **metadata only**:

- it never executes a command;
- it never writes or modifies a learner's files;
- it never grades work or assesses answers;
- it never persists progress.

## Command

```bash
# Overview of the whole path (11 steps)
duke learn T1078

# One full lesson by its stable step id
duke learn T1078 --step detection
duke learn T1078 --step investigation
duke learn T1078 --step final-challenge
```

Exit codes follow Duke's convention:

- `0` — overview rendered, or a valid lesson rendered;
- `2` — unsupported technique (anything other than `T1078`), or an unknown
  step id.

Output is rendered as **literal plain text**. Brackets, dictionaries, and
type annotations in code snippets are shown verbatim and are never
interpreted as Rich markup or reformatted.

## Step catalogue

Each step has a stable id (`duke learn T1078 --step <id>`), an ordinal, a
security objective, Python concepts, an explanation with code, real CLI
command examples, a hands-on exercise with an expected observable result,
hints, a knowledge check, and an explicit safety note.

| Ordinal | Id | Title | Python concepts |
|---:|---|---|---|
| 1 | `orientation` | Orientation and safety | scenario reading, CLI usage, synthetic data |
| 2 | `collections` | Python collections | lists, dictionaries, iteration, attribute access |
| 3 | `typed-models` | Typed models and validation | Pydantic models, typed fields, validation, immutability |
| 4 | `datetime` | Datetime arithmetic and the correlation window | datetime, timedelta, aware datetimes, comparison |
| 5 | `functions-modules` | Functions and modules | functions, modules, imports, return values, tuples |
| 6 | `detection` | Detection reasoning | confidence scoring, thresholds, conditionals |
| 7 | `investigation` | Evidence-led investigation | sorting, key functions, UUIDs, relationships |
| 8 | `response` | Safe response planning | StrEnum, boolean flags, attributes |
| 9 | `validation` | Detection validation | immutability, model_copy, deterministic tests, booleans |
| 10 | `reporting` | Reporting | structured data, deterministic rendering, strings |
| 11 | `final-challenge` | Final challenge: the full learning loop | pipelines, function composition, verification |

All code and commands use documented public package exports and real CLI
syntax — never private helpers or internal constants. For example, the
detection lesson explains the documented confidence threshold of 60 as a
value read from the `Finding`, and does not ask the learner to import an
internal constant.

## Learning through the T1078 workflow

The path maps one-to-one onto Duke's implemented T1078 pipeline, so each
lesson links to the component that owns that stage:

- Step 1 grounds the learner in the scenario and hard safety boundary.
- Steps 2–5 teach core Python (collections, typed models, datetimes,
  functions and modules) on real T1078 data and functions.
- Steps 6–10 map onto the implemented pipeline stages — detection,
  investigation, response, validation, and reporting — each pointing at the
  matching component documentation below.
- Step 11 is an end-to-end challenge connecting every stage; it instructs
  only and never runs, grades, or persists.

Stage links:

- Detection — [docs/validation](../validation/T1078-detection-validation.md)
  and [docs/detections](../detections)
- Investigation — [docs/investigations](../investigations/T1078-compromised-identity.md)
- Response — [docs/responses](../responses/T1078-safe-response.md)
- Validation — [docs/validation](../validation/T1078-detection-validation.md)
- Reporting — [docs/reporting](../reporting/T1078-incident-reporting.md)
- End-to-end lab — [docs/labs/T1078/overview.md](../labs/T1078/overview.md)
- Domain models — [docs/architecture/domain-model.md](../architecture/domain-model.md)

## Safety

Guided learning respects the same safety policy as the rest of Duke. Lessons
teach *observation* and *response planning*, never offensive capability:

- artefact data is synthetic and disposable;
- nothing touches a real account, session, file, network, or security
  control;
- response actions are dry-run and approval-gated, never executed;
- commands shown are instructions for the learner to run in their own
  isolated lab, not executed by Duke's learning model.

## Planned

The learning component is not complete. Remaining learning work is planned
and out of scope for this milestone:

- additional ATT&CK scenarios and their learning paths;
- a reusable scenario registry/orchestration (technical overhaul of the
  catalogue-to-CLI wiring);
- programmable learner-progress tracking and resumability (Duke currently
  persists no learning state);
- broader "improve → retest" learning workflows that loop detection tuning
  back into lessons;
- persistence, adapters, an API, and a TUI/Web UI for learning;
- further guided lesson content and exercises.

None of the above changes Duke's commitment that learning remains metadata
and never executes, modifies, or grades automatically.

## References

- [ROADMAP.md](../../ROADMAP.md)
- [CHANGELOG.md](../../CHANGELOG.md)
- [docs/architecture/overview.md](../architecture/overview.md)
- [docs/development/testing.md](../development/testing.md)

Last reviewed: 2026-09-22
