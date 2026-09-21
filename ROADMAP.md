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

- Installable Python package (`duke-security`)
- Typer/Rich command-line interface
- `duke --help`
- `duke version`
- CLI unit tests
- Quality gates: Ruff, mypy (strict), pytest
- Documentation foundation (this roadmap, README, CONTRIBUTING,
  architecture overview, development guides, and initial ADRs)

### Planned

All components below are planned and not yet implemented.

| Component | Purpose |
|---|---|
| `core` | Shared domain models, interfaces, configuration, and registry |
| `cli` | Typer-based command-line interface (foundation in place; commands to grow with each capability) |
| `learning` | Python lessons, exercises, and challenges |
| `simulation` | Safe behaviour and scenario simulation |
| `telemetry` | Normalized security-event generation and ingestion |
| `detection` | Detection rules, correlation, and quality testing |
| `investigation` | Evidence, timelines, hypotheses, and graphs |
| `response` | Safe response plans, approvals, dry runs, and rollback |
| `reporting` | Incident reports, summaries, and lessons learned |
| `labs` | Guided end-to-end learning experiences |
| `adapters` | Optional vendor or platform integrations |

The core will not depend directly on AWS, Azure, GCP, a particular
SIEM, EDR, or other security vendor. Provider-specific data is
translated into Duke's normalized models through adapters — see
[ADR 0001](docs/decisions/0001-vendor-agnostic-core.md).

Planned domain models (introduced only with clear purpose, tests, and
documentation): `SecurityEvent`, `Entity`, `Evidence`, `Finding`,
`Incident`, `ResponseAction`, `Scenario`.

## Beyond the first milestone

Once the T1078 vertical slice is complete and validated, Duke intends
to grow its scenario catalogue to cover additional ATT&CK tactics and
techniques, always built and documented as complete vertical slices
rather than partial, cross-cutting layers. The scenario catalogue is
metadata-driven and is not hardcoded into the CLI.
