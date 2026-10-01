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
- **T1110 — Brute Force** — a second production scenario now providing the
  **full seven-capability lifecycle** (`duke simulate/detect/investigate/
  respond/validate/report/learn T1110`), joining the full-lifecycle conformance
  fixture set. It reproducibly models the observable telemetry of sub-technique
  **T1110.003 Password Spraying** and never performs real authentication,
  stores or implies a credential value, or labels any account as compromised.
  `duke learn T1110` provides a defensive 11-step guided learning path.
  Broader future work — additional scenarios, adapters, a GUI/API, progress
  tracking, auto-grading, and real response execution — remains **planned**
- Documentation foundation (this roadmap, README, CONTRIBUTING,
  architecture overview, development guides, initial ADRs, and the guided
  learning guide under `docs/learning/`)
- Documentation foundation (this roadmap, README, CONTRIBUTING,
  architecture overview, development guides, initial ADRs, and the guided
  learning guide under `docs/learning/`)

### Current phase

The **two-scenario milestone is complete**: T1078 and T1110 are both
full-lifecycle production verticals (each exposing simulation, detection,
investigation, response, validation, reporting, and learning). The current
phase is **Phase 1 — portfolio / release preparation**: architecture
diagrams, lifecycle/data-flow diagram, a concise README showcase, a
reproducible demonstration, and a release-readiness review.

The forward roadmap, in order:

- **Phase 1 — Portfolio / release preparation** *(current)*: architecture
  and lifecycle diagrams, README showcase, reproducible demonstration,
  version/release-readiness review.
- **Phase 2 — Narrow T1566 simulation**: a single, deterministic,
  defensive simulation of a proposed future scenario based on
  **T1566.002 Spearphishing Link**. **T1566 is proposed, not implemented
  or registered**; this roadmap describes the ordering only and commits
  to no event-level design.
- **Phase 3 — T1566 detection through learning**: detection, investigation,
  response, validation, reporting, and learning for T1566, one reviewed
  slice at a time.
- **Phase 4 — Evidence-backed refactoring future work**: shared helper
  extractions only when each third implementation exists (rule of three).

A **`0.2.0` release is pending separate approval** and is not performed by
the portfolio slice. Its scope is the completed T1078 + T1110 portfolio plus
the portfolio documentation; T1566 is outside that scope. See
[docs/release/0.2.0-release-readiness.md](docs/release/0.2.0-release-readiness.md).

## Component roadmap

The core domain models and CLI foundation are implemented. The table
below distinguishes that foundation from the capabilities still planned.

| Component | Purpose |
|---|---|
| `core` | Domain models implemented; shared interfaces and configuration planned |
| `scenarios` | Static built-in scenario registry implemented (`duke.scenarios`), registering T1078 and T1110 once with typed capabilities and metadata loaders; all CLI commands resolve scenarios and dispatch to capabilities through the registry. Dynamic/plugin discovery and configuration-driven registries remain planned |
| `cli` | Typer-based CLI implemented with `version`, `scenarios`, and all seven T1078 lifecycle commands plus all seven T1110 lifecycle commands (simulation, detection, investigation, response, validation, reporting, learning); commands resolve scenarios and their capabilities through the static built-in scenario registry (`duke.scenarios`), so additional scenarios are addable by registration rather than CLI edits, and missing capabilities fail clearly with exit code 2 |
| `learning` | T1078 and T1110 guided learning paths implemented (`duke learn T1078`/`duke learn T1110`) with typed, metadata-only learning models and deterministic rendering; learner-progress tracking, broader improve→retest learning workflows, and further lesson content remain planned |
| `simulation` | T1078 and T1110 safe deterministic simulations implemented; additional scenarios and mutation remain planned |
| `telemetry` | Normalized event generation, JSON export, and artefact ingestion implemented; source health and broader ingestion remain planned |
| `detection` | Deterministic T1078 detection implemented with explainable weighted confidence; deterministic T1110 password-spraying detection implemented via a sliding-window rule (hard gate of ≥5 distinct failed accounts in 30 minutes, later success credited only as supporting evidence, never assuming compromise, earliest-starting window tie-break); deterministic T1110 detection validation (`duke validate T1110`) with a fixed ordered 19-case catalogue over immutable in-memory mutations and an exhaustiveness test; T1078 detection validation (`duke validate`) with controlled in-memory mutations and an explicit case suite; precision/recall measurement, lifecycle tuning, and additional rules remain planned |
| `investigation` | Evidence-led T1078 investigation implemented (`duke investigate`) producing timelines, evidence, involved entities, facts, assessments, and open questions; deterministic T1110 password-spraying investigation implemented with finding-scoped evidence, chronological timeline (time then ID), cautious facts/assessments/questions, and no compromise or attribution claims; hypothesising and graphs remain planned |
| `response` | Dry-run-only T1078 response planning implemented (`duke respond`), producing preliminary-incident correlation and approval-gated actions grouped by category; deterministic T1110 password-spraying response planning implemented with evidence-led source/success-account target resolution, conditional and proportionate source containment, temporary reversible step-up authentication, and conservative rollback (session/credential changes irreversible, evidence never deleted); real execution, approvals, and rollback application remain planned |
| `reporting` | Deterministic advisory incident reporting implemented (`duke report`), aggregating finding, investigation, dry-run response plan, and validation into byte-deterministic Markdown with atomic overwrite-protected export; deterministic T1110 report (`duke report T1110`) with a scenario-agnostic renderer, T1110 entity roles, validation-once/exactly-one-finding flow, and byte-identical T1078 output preserved; PDF/HTML output and lessons-learned remain planned |
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

With the two-scenario vertical slice complete and validated, Duke intends
to grow its scenario catalogue to cover additional ATT&CK tactics and
techniques, always built and documented as complete vertical slices rather
than partial, cross-cutting layers. The scenario catalogue is
metadata-driven and is not hardcoded into the CLI.

New scenarios are added as small vertical slices. T1110 is now a complete
seven-capability vertical: it began as a **simulation-only** slice and added
**detection**, **investigation**, **response planning**, **validation**,
**incident reporting**, and finally **guided learning**, joining the
full-lifecycle conformance fixture set. Each step proved the multi-scenario
foundation and the registry's safe missing-capability behaviour.

**Proposed future work** (not yet implemented or registered):

- **T1566.002 Spearphishing Link** as the third scenario vertical —
  proposed, under active design, and out of scope for the current
  portfolio slice and for the `0.2.0` release. This roadmap commits to
  the *ordering* above, not to any event-level design.
- **Later lifecycle slices and evidence-backed refactoring** — shared-helper
  extraction only once a third implementation exists for each candidate
  (e.g. simulation builder, investigation scaffold, response action
  builder, validation harness, reporting aggregation, learning step
  builder), each separately reviewable and preserving existing T1078/T1110
  outputs.
