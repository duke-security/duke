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
- Documentation foundation (this roadmap, README, CONTRIBUTING,
  architecture overview, development guides, and initial ADRs)

### Component roadmap

The core domain models and CLI foundation are implemented. The table
below distinguishes that foundation from the capabilities still planned.

| Component | Purpose |
|---|---|
| `core` | Domain models implemented; shared interfaces, configuration, and scenario registry planned |
| `cli` | Typer-based CLI implemented with `version` and T1078 `simulate`; commands will grow with each capability |
| `learning` | Python lessons, exercises, and challenges |
| `simulation` | T1078 safe deterministic simulation implemented; additional scenarios and mutation remain planned |
| `telemetry` | Normalized event generation, JSON export, and artefact ingestion implemented; source health and broader ingestion remain planned |
| `detection` | Deterministic T1078 detection implemented with explainable weighted confidence; deterministic detection validation implemented (`duke validate`) with controlled in-memory mutations and an explicit case suite; precision/recall measurement, lifecycle tuning, and additional rules remain planned |
| `investigation` | Evidence-led T1078 investigation implemented (`duke investigate`), producing timelines, evidence, involved entities, facts, assessments, and open questions; hypothesising and graphs remain planned |
| `response` | Dry-run-only T1078 response planning implemented (`duke respond`), producing preliminary-incident correlation and approval-gated actions grouped by category; real execution, approvals, and rollback application remain planned |
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
