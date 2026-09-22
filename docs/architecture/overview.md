# Architecture Overview

Duke is a vendor-agnostic, interactive cybersecurity education and
security-engineering platform. Its architecture is organized around a
continuous lifecycle:

```
Learn → Simulate → Observe → Detect → Investigate → Respond →
Validate → Document → Improve → Retest
```

Each stage of the lifecycle maps to a component boundary in Duke's
design. This separation keeps every stage independently testable and
lets learners see how a real security-engineering workflow is
composed, rather than experiencing it as a single opaque tool.

## Current implementation

The following foundations are implemented:

- **`core`** — vendor-neutral models for entities, security events,
  evidence, findings, incidents, response actions, and scenarios.
- **`cli`** — Typer/Rich commands for help, version information, and
  running the T1078 simulation.
- **`scenarios`** — packaged YAML definitions loaded and validated as
  typed `Scenario` models.
- **`simulation`** — a deterministic and safe T1078 event generator.
- **`telemetry`** — normalized synthetic events and structured JSON
  export with overwrite protection.
- **`labs`** — documentation for the implemented T1078 simulation
  stage.

The T1078 detection, investigation, response, validation, reporting,
and learning stages remain planned.

## Component status

| Component | Current status and responsibility |
|---|---|
| `core` | Domain models implemented; shared interfaces, configuration, and registry remain planned |
| `cli` | Foundation, `version`, and T1078 `simulate` implemented |
| `learning` | Planned Python lessons, exercises, and challenges |
| `simulation` | T1078 deterministic simulation implemented; additional scenarios and mutation planned |
| `telemetry` | T1078 event generation and JSON export implemented; ingestion and source-health monitoring planned |
| `detection` | Planned detection rules, correlation, testing, and tuning |
| `investigation` | Planned evidence, timelines, hypotheses, and graphs |
| `response` | Planned safe response actions, approvals, dry runs, verification, and rollback |
| `reporting` | Planned incident reports, summaries, and lessons learned |
| `labs` | T1078 simulation documentation implemented; remaining lifecycle stages planned |
| `adapters` | Planned optional vendor and platform integrations |

## Vendor-agnostic core

Duke's core must not depend directly on AWS, Azure, GCP, a particular
SIEM, EDR, or other security vendor. Provider-specific data is
translated into Duke's normalized internal models exclusively through
adapters. This means:

- `simulation`, `telemetry`, `detection`, `investigation`, `response`,
  and `reporting` all operate on normalized models, never on
  vendor-specific payloads directly.
- Adding support for a new vendor or platform means writing a new
  adapter, not modifying the core.

See [ADR 0001](../decisions/0001-vendor-agnostic-core.md) for the
rationale.

## Domain model

The core domain model — `SecurityEvent`, `Entity`, `Evidence`,
`Finding`, `Incident`, `ResponseAction`, and `Scenario` — is
implemented; see [domain-model.md](domain-model.md) for each model's
purpose, relationships, and key validation decisions. Further models
are introduced incrementally, only with a clear purpose, tests, and
documentation — not speculatively.


## Scenario design

Scenarios are metadata-driven rather than hardcoded into the CLI.

The implemented T1078 scenario contains:

- packaged `scenario.yaml` metadata;
- a typed YAML loader with Pydantic validation;
- ATT&CK technique and multiple-tactic mappings;
- learning objectives and Python concepts;
- telemetry requirements and explicit safety notes;
- deterministic safe simulation logic;
- automated model, loader, simulation, export, and CLI tests;
- scenario documentation.

The following scenario components remain planned:

- detection logic and quality tests;
- investigation and evidence guidance;
- safe response actions;
- validation and mutation testing;
- incident reporting;
- guided learning exercises.

T1078 Valid Accounts is Duke's first vertical slice, not its only
planned scenario. See [ROADMAP.md](../../ROADMAP.md) and the
[T1078 lab documentation](../labs/T1078/overview.md).


## CLI-first interface

Duke builds its command-line interface before any API, TUI, or web
interface. See [ADR 0002](../decisions/0002-cli-first.md).

## Safe simulation of adversary behaviour

Duke reproduces the observable effects of adversary behaviour using
synthetic data and isolated environments, rather than implementing
offensive capability. See
[ADR 0003](../decisions/0003-safe-synthetic-simulations.md).
