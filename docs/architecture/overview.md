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

Only two components are implemented today:

- **`core`** — currently limited to package metadata; the shared
  domain models, interfaces, configuration, and registry described
  below are planned.
- **`cli`** — a Typer-based command-line interface providing
  `duke --help` and `duke version`, built on top of Rich for output
  formatting.

Everything else in this document describes planned architecture.

## Planned components

| Component | Responsibility |
|---|---|
| `core` | Shared domain models, interfaces, configuration, and a scenario/component registry |
| `cli` | Typer-based command-line interface; the primary interface until an API, TUI, or web UI is justified |
| `learning` | Python lessons, exercises, and challenges |
| `simulation` | Safe behaviour and scenario simulation |
| `telemetry` | Normalized security-event generation and ingestion |
| `detection` | Detection rules, correlation, and quality testing |
| `investigation` | Evidence, timelines, hypotheses, and graphs |
| `response` | Safe response plans, approvals, dry runs, and rollback |
| `reporting` | Incident reports, summaries, and lessons learned |
| `labs` | Guided end-to-end learning experiences that compose the components above into a full lifecycle |
| `adapters` | Optional vendor or platform integrations |

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

## Domain model direction

The initial domain model will eventually include: `SecurityEvent`,
`Entity`, `Evidence`, `Finding`, `Incident`, `ResponseAction`, and
`Scenario`. These are introduced incrementally, only with a clear
purpose, tests, and documentation — not speculatively.

## Scenario design

Scenarios are intended to be metadata-driven rather than hardcoded
into the CLI. A scenario may eventually be composed of:

- `scenario.yaml` metadata (identifier, name, description, ATT&CK
  technique/tactic, learning objectives, Python concepts, telemetry
  requirements, safety classification, references, version, and
  last-reviewed date)
- safe simulation logic
- detection logic
- investigation guidance
- response guidance
- validation tests
- scenario documentation

The first scenario, based on MITRE ATT&CK T1078 (Valid Accounts), is
the initial vertical slice used to validate this design end to end —
see [ROADMAP.md](../../ROADMAP.md).

## CLI-first interface

Duke builds its command-line interface before any API, TUI, or web
interface. See [ADR 0002](../decisions/0002-cli-first.md).

## Safe simulation of adversary behaviour

Duke reproduces the observable effects of adversary behaviour using
synthetic data and isolated environments, rather than implementing
offensive capability. See
[ADR 0003](../decisions/0003-safe-synthetic-simulations.md).
