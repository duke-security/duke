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

Two companion documents go deeper and are the best starting points:

- [components.md](components.md) — the component diagram and each
  component's role and implementation status.
- [lifecycle.md](lifecycle.md) — the pedagogy lifecycle versus the
  concrete data flow the CLI implements today.

## Current implementation

The following foundations are implemented:

- **`core`** — vendor-neutral models for entities, security events,
  evidence, findings, incidents, response actions, and scenarios.
- **`cli`** — Typer/Rich commands for help, version information, the
  `scenarios` listing, and all seven lifecycle commands for both the T1078
  and T1110 scenarios. Commands resolve scenarios and dispatch to
  capabilities through the static built-in registry rather than hardcoding
  a technique.
- **`scenarios`** — a static built-in scenario registry that registers
  T1078 and T1110 (`ScenarioRegistration`) with a lazy metadata loader and
  seven typed optional capabilities, plus packaged YAML definitions
  loaded and validated as typed `Scenario` models. The CLI resolves
  scenarios and dispatches to capabilities through this registry.
- **`simulation`** — deterministic and safe T1078 and T1110 event
  generators.
- **`telemetry`** — normalized synthetic events, structured JSON export
  with overwrite protection, and artefact ingestion that loads validated
  `Entity` and `SecurityEvent` collections from exported JSON.
- **`detection`** — deterministic, behaviour-based detection (T1078 and
  T1110) that scores an actor's event sequence with an explainable
  weighted confidence value and emits vendor-neutral `Finding` objects.
  Artefact loading and validation live in `telemetry` and are re-exported
  here for compatibility.
- **`investigation`** — evidence-led T1078 and T1110 investigation that
  consumes an existing `Finding` and produces a chronological timeline,
  per-event evidence, involved entities, confirmed facts, analyst
  assessments, and unresolved questions.
- **`response`** — dry-run-only T1078 and T1110 response planning that
  correlates a finding into a deterministic preliminary incident and
  proposes approval-gated actions grouped into containment, evidence
  preservation, investigation follow-up, and recovery.
- **`validation`** — deterministic validation of the detection →
  investigation → response pipeline that reruns the workflow against
  controlled in-memory mutations of an artefact, never modifying it.
- **`reporting`** — deterministic, advisory incident reporting that
  aggregates the existing finding, investigation, dry-run response plan,
  and validation suite into a byte-deterministic Markdown report, exported
  with overwrite protection.
- **`learning`** — guided learning paths: typed, metadata-only learning
  models and deterministic rendering (`duke learn T1078`,
  `duke learn T1110`) that teach Python through Duke's implemented
  workflow without executing commands, modifying learner files, grading,
  or persisting progress.
- **`labs`** — documentation for the implemented T1078 and T1110
  simulation, detection, investigation, response, validation, reporting,
  and guided learning stages.

## Component status

| Component | Current status and responsibility |
|---|---|
| `core` | Domain models implemented; shared interfaces and configuration remain planned |
| `scenarios` | Static built-in scenario registry implemented, registering T1078 and T1110 with typed capabilities and a lazy metadata loader; dynamic/plugin discovery and configuration-driven registries remain planned |
| `cli` | Typer/Rich CLI implemented with `version`, `scenarios`, and all seven lifecycle commands for both T1078 and T1110; commands resolve scenarios and dispatch to capabilities through the `scenarios` registry |
| `learning` | Guided learning paths implemented (`duke learn T1078`, `duke learn T1110`); learner-progress tracking and further learning content remain planned |
| `simulation` | T1078 and T1110 deterministic simulation implemented; additional scenarios and mutation planned |
| `telemetry` | Normalized event generation, JSON export, and artefact ingestion implemented; source-health monitoring and broader ingestion planned |
| `detection` | Deterministic T1078 and T1110 detection implemented with explainable weighted confidence; detection validation implemented (`duke validate`); precision/recall, tuning, and additional rules planned |
| `investigation` | Evidence-led T1078 and T1110 investigation implemented (`duke investigate`); hypothesising and graphs remain planned |
| `response` | Dry-run-only T1078 and T1110 response planning implemented (`duke respond`); execution, approvals, and rollback application remain planned |
| `validation` | Deterministic validation implemented (`duke validate`), rerunning the pipeline against in-memory mutations of an artefact |
| `reporting` | Deterministic advisory incident reporting implemented (`duke report`), rendering an aggregate of finding, investigation, response plan, and validation suite to Markdown with overwrite-protected export |
| `learning` | T1078 and T1110 guided learning paths implemented with typed, metadata-only models and deterministic literal rendering; learner-progress tracking and further learning content remain planned |
| `labs` | T1078 simulation through reporting documentation implemented (labs overview covers all lifecycle stages); guided lab delivery remains planned |
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

The implemented scenario now also includes:

- behaviour-based detection logic with explainable weighted confidence
  and automated tests;
- evidence-led investigation guidance that consumes an existing finding
  and produces evidence, a timeline, involved entities, facts,
  assessments, and open questions;
- safe dry-run response planning that proposes approval-gated actions
  grouped by category, without ever executing them;
- deterministic detection validation that reruns the pipeline against
  controlled in-memory mutations, without modifying the source artefact;
- deterministic advisory incident reporting that aggregates the workflow
  data into a Markdown report without asserting confirmed compromise,
  impact, or exfiltration;
- a guided learning path that teaches Python through the implemented
  workflow, reusing the real CLI commands and public exports as metadata
  without executing them. See
  [the T1078 guided learning guide](../learning/T1078-guided-learning.md)
  and [the T1110 guided learning guide](../learning/T1110-guided-learning.md).

Both **T1078 Valid Accounts** and **T1110 Brute Force (Password
Spraying)** are completed two-production-scenario full-lifecycle verticals:
each exposes all seven registered capabilities
(simulation, detection, investigation, response, validation, reporting,
learning).

Scenarios are registered in a **static built-in scenario registry**
(`duke.scenarios`), not discovered from the filesystem. Each registration
declares a technique ID, slug, name, aliases, a lazy metadata loader, and
seven typed optional capabilities; the CLI resolves scenarios by ID, slug,
or alias and dispatches each lifecycle command through the registry. This
keeps scenario orchestration in one place: adding a scenario means adding a
registration, not editing every CLI command. See
[scenario-registry.md](../scenarios/scenario-registry.md). Dynamic/plugin
discovery is deliberately deferred.

The following scenario components remain planned:

- additional ATT&CK scenarios and their learning paths;
- dynamic/plugin scenario discovery;
- learner-progress tracking;
- broader improve → retest learning workflows.

T1078 Valid Accounts is Duke's first vertical slice, and
T1110 Brute Force is the second completed full-lifecycle vertical;
together they are the current two-scenario production portfolio. More
scenarios are planned. See [ROADMAP.md](../../ROADMAP.md) and the
[T1078 lab documentation](../labs/T1078/overview.md) and
[T1110 lab documentation](../labs/T1110/overview.md).


## CLI-first interface

Duke builds its command-line interface before any API, TUI, or web
interface. See [ADR 0002](../decisions/0002-cli-first.md).

## Safe simulation of adversary behaviour

Duke reproduces the observable effects of adversary behaviour using
synthetic data and isolated environments, rather than implementing
offensive capability. See
[ADR 0003](../decisions/0003-safe-synthetic-simulations.md).
