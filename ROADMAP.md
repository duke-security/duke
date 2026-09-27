# Roadmap

Duke is built in small, independently testable vertical slices rather
than by implementing entire layers at once. This roadmap describes
the current milestone, the planned architecture, and how future
scenarios extend beyond it.

## Lifecycle

Every scenario in Duke, present or future, is meant to exercise this
lifecycle end to end:

```
Learn → Simulate → Observe → Detect → Investigate → Respond →
Validate → Document → Improve → Retest
```

## Current milestone: T1078 — Valid Accounts

The first milestone is one complete, end-to-end scenario based on
[MITRE ATT&CK T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/).
It exists to prove out Duke's architecture across the full lifecycle,
not to be the only scenario Duke supports. It must demonstrate:

1. Safe scenario simulation
2. Normalized telemetry generation
3. Behaviour-based detection
4. Evidence-led investigation
5. Safe dry-run response
6. Detection validation
7. Professional incident reporting
8. Tests and documentation

Additional ATT&CK techniques and tactics are expected to follow once
this vertical slice is complete, but are intentionally out of scope
for the current milestone.

## Status

### Complete

- Packaged YAML scenario loading and validation
- T1078 deterministic simulation with eight entities and eight events
- Normalized JSON telemetry export with overwrite protection
- `duke simulate T1078`
- T1078 simulation documentation and automated tests
- Vendor-neutral Pydantic v2 core domain models with strict validation
- Core domain-model unit tests and architecture documentation
- Installable Python package (`duke-security`)
- Typer/Rich command-line interface
- `duke --help`
- `duke version`
- CLI unit tests
- Quality gates: Ruff, mypy (strict), pytest
- `duke detect T1078`
- Deterministic, behaviour-based T1078 detection using an explainable
  weighted confidence score (`Finding.confidence`) over normalized events
- Detection input loading and validation with clear error handling, plus
  comprehensive detection and CLI tests
- Telemetry artefact ingestion through `duke.telemetry` (entities + events),
  re-exported by `duke.detection` for backwards compatibility
- `duke investigate T1078`
- Evidence-led T1078 investigation that consumes an existing finding and
  produces a chronological timeline, per-event evidence (with the known-good
  baseline as context), involved entities, confirmed facts, analyst
  assessments, and unresolved questions — plus benign no-finding handling
  and comprehensive investigation, loader, and CLI tests
- `duke respond T1078`
- Safe dry-run-only T1078 response planning (`plan_t1078_response`) that
  correlates a finding into a deterministic preliminary incident and
  proposes approval-gated actions grouped into containment, evidence
  preservation, investigation follow-up, and recovery — with conservative
  rollback semantics, verified via model, planner, and CLI tests
- `duke validate T1078`
- Deterministic T1078 detection validation (`validate_t1078`) that consumes
  an artefact (never modifying it), reruns detection, investigation, and
  response planning against controlled in-memory mutations, and reports a
  read-only `all_passed` suite of explicit cases — with a side-effect-free
  guard and comprehensive validation, mutation, and CLI tests
- `duke report T1078`
- Deterministic, advisory incident reporting (`report_t1078` +
  `render_incident_report`) that aggregates the existing finding,
  investigation, dry-run response plan, and validation suite into a
  byte-deterministic Markdown report — with safe overwrite-protected export,
  and without asserting confirmed compromise, impact, or exfiltration
- `duke learn T1078`
- A T1078 guided learning path: 11 deterministic, beginner-friendly steps
  that teach Python through Duke's defensive T1078 workflow, using real CLI
  commands and public exports as metadata — never executing commands,
  modifying learner files, grading, or persisting progress
- `duke scenarios`
- A static built-in scenario registry (`duke.scenarios`) that registers T1078
  once with a typed, frozen `ScenarioRegistration` — technique ID, slug, name,
  aliases, a lazy metadata loader, and seven typed optional capabilities —
  resolved case-insensitively. Every CLI lifecycle command now resolves
  scenarios and dispatches to capabilities through the registry instead of
  hardcoding T1078, so future scenarios are addable by registration rather
  than edits across every command; missing capabilities and unknown scenarios
  fail clearly with exit code 2
- Reusable, test-only scenario-conformance infrastructure
  (`tests/conformance/`): the same declaration, registry, and behavioural
  checks validate both the built-in T1078 scenario and an independent probe
  scenario, with negative tests proving each authoring invariant is enforced
  and an AST-based import guard confirming the conformance sources never
  depend on a `duke.*.t1078` implementation module. Conformance lives under
  `tests/` only — no runtime conformance code in the `duke` package — and is
  documented under `docs/scenarios/`
- **T1110 — Brute Force** simulation/detection/investigation/response/
  validation slice (`duke simulate T1110` / `duke detect T1110` /
  `duke investigate T1110` / `duke respond T1110` / `duke validate T1110`): a
  second production scenario providing **simulation, detection,
  investigation, response planning, and validation**. It reproducibly models
  the observable telemetry of sub-technique **T1110.003 Password Spraying** —
  a benign baseline authentication, six evenly-spaced failed authentications
  against distinct accounts from a single external source, and one later
  success. It never performs real authentication, stores or implies a
  credential value, or labels any account as compromised. `duke detect T1110`
  reports the spray pattern as a deterministic finding (a sliding 30-minute
  window requiring at least five distinct failed accounts from one source; a
  later success is credited only as supporting evidence; compromise is never
  assumed). `duke investigate T1110` produces an evidence-led timeline,
  cautious confirmed facts, and unresolved questions without ever claiming
  compromise or attribution. `duke respond T1110` proposes a dry-run-only,
  approval-gated response plan with evidence-led targets (the source and a
  verified success-associated account), conditional and proportionate source
  containment, and conservative rollback; it never executes anything.
  `duke validate T1110` proves the pipeline with an ordered 19-case,
  deterministic validation suite (19/19 passing on the canonical corpus),
  never mutating the source artefact or input file. Unsupported T1110
  lifecycle commands (report, learn) fail safely with exit code 2 through the
  registry's missing-capability path. Reporting and learning for T1110 are
  intentionally **planned**
- Documentation foundation (this roadmap, README, CONTRIBUTING,
  architecture overview, development guides, initial ADRs, and the guided
  learning guide under `docs/learning/`)

### Component roadmap

The core domain models and CLI foundation are implemented. The table
below distinguishes that foundation from the capabilities still planned.

| Component | Purpose |
|---|---|
| `core` | Domain models implemented; shared interfaces and configuration planned |
| `scenarios` | Static built-in scenario registry implemented (`duke.scenarios`), registering T1078 and T1110 once with typed capabilities and metadata loaders; all CLI commands resolve scenarios and dispatch to capabilities through the registry. Dynamic/plugin discovery and configuration-driven registries remain planned |
| `cli` | Typer-based CLI implemented with `version`, `scenarios`, and all seven T1078 lifecycle commands plus T1110 simulation, detection, investigation, response, and validation; commands resolve scenarios and their capabilities through the static built-in scenario registry (`duke.scenarios`), so additional scenarios are addable by registration rather than CLI edits, and missing capabilities fail clearly with exit code 2 |
| `learning` | T1078 guided learning path implemented (`duke learn T1078`) with typed, metadata-only learning models and deterministic rendering; learner-progress tracking, broader improve→retest learning workflows, and further lesson content remain planned |
| `simulation` | T1078 and T1110 safe deterministic simulations implemented; additional scenarios and mutation remain planned |
| `telemetry` | Normalized event generation, JSON export, and artefact ingestion implemented; source health and broader ingestion remain planned |
| `detection` | Deterministic T1078 detection implemented with explainable weighted confidence; deterministic T1110 password-spraying detection implemented via a sliding-window rule (hard gate of ≥5 distinct failed accounts in 30 minutes, later success credited only as supporting evidence, never assuming compromise, earliest-starting window tie-break); deterministic T1110 detection validation (`duke validate T1110`) with a fixed ordered 19-case catalogue over immutable in-memory mutations and an exhaustiveness test; T1078 detection validation (`duke validate`) with controlled in-memory mutations and an explicit case suite; precision/recall measurement, lifecycle tuning, and additional rules remain planned |
| `investigation` | Evidence-led T1078 investigation implemented (`duke investigate`) producing timelines, evidence, involved entities, facts, assessments, and open questions; deterministic T1110 password-spraying investigation implemented with finding-scoped evidence, chronological timeline (time then ID), cautious facts/assessments/questions, and no compromise or attribution claims; hypothesising and graphs remain planned |
| `response` | Dry-run-only T1078 response planning implemented (`duke respond`), producing preliminary-incident correlation and approval-gated actions grouped by category; deterministic T1110 password-spraying response planning implemented with evidence-led source/success-account target resolution, conditional and proportionate source containment, temporary reversible step-up authentication, and conservative rollback (session/credential changes irreversible, evidence never deleted); real execution, approvals, and rollback application remain planned |
| `reporting` | Deterministic advisory incident reporting implemented (`duke report`), aggregating finding, investigation, dry-run response plan, and validation into byte-deterministic Markdown with overwrite-protected export; PDF/HTML output and lessons-learned remain planned |
| `labs` | T1078 simulation through reporting documentation implemented (labs overview covers all lifecycle stages); guided lab delivery remains planned |
| `adapters` | Optional vendor or platform integrations |

The core will not depend directly on AWS, Azure, GCP, a particular
SIEM, EDR, or other security vendor. Provider-specific data is
translated into Duke's normalized models through adapters — see
[ADR 0001](docs/decisions/0001-vendor-agnostic-core.md).

Implemented domain models: `SecurityEvent`, `Entity`, `Evidence`,
`Finding`, `Incident`, `ResponseAction`, and `Scenario`. See
[domain-model.md](docs/architecture/domain-model.md). Further models
will be introduced only with clear purpose, tests, and documentation.

## Beyond the first milestone

Once the T1078 vertical slice is complete and validated, Duke intends
to grow its scenario catalogue to cover additional ATT&CK tactics and
techniques, always built and documented as complete vertical slices
rather than partial, cross-cutting layers. The scenario catalogue is
metadata-driven and is not hardcoded into the CLI.

New scenarios are added as small vertical slices. T1110 progresses slice by
slice: it began as a **simulation-only** slice, added **detection**,
**investigation**, **response planning**, and now **validation**, while its
remaining lifecycle capabilities (reporting, learning) are intentionally
not yet provided. Each step proves the multi-scenario foundation and the
registry's safe missing-capability behaviour before the rest of the T1110
vertical is built.
