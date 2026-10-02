# Scenario Authoring

Duke's authoring contract for a new scenario is the combination of a
typed `ScenarioRegistration` (with its lazy metadata loader) and the exact
capability callable signatures that `duke.scenarios.registry` already
defines. There is **no separate authoring Protocol**: the callable aliases
and `ScenarioCapabilities` fields *are* the contract. This page explains
what a scenario author must provide and how the lifecycle dependencies
between capabilities are framed.

## The contract in one sentence

A scenario provides metadata plus zero or more of the seven lifecycle
capabilities, each typed to an exact callable alias, and wraps them in a
`ScenarioRegistration` that a registry can resolve by technique ID, slug,
or alias.

## Capability callable signatures (the exact contract)

These aliases are defined in `duke.scenarios.registry` and are the typed
public surface a scenario author implements:

| Capability | Callable alias | Signature (result) |
|---|---|---|
| simulation | `SimulationRun` | `Callable[..., SimulationResult]` |
| detection | `DetectRun` | `Callable[..., tuple[Finding, ...]]` |
| investigation | `InvestigateRun` | `Callable[[TelemetryArtefact, Finding], InvestigationResult]` |
| response | `ResponsePlanRun` | `Callable[[TelemetryArtefact, InvestigationResult], ResponsePlan]` |
| validation | `ValidationRun` | `Callable[[TelemetryArtefact], ValidationSuiteResult]` |
| reporting | `ReportRun` | `Callable[[TelemetryArtefact, Finding, InvestigationResult, ResponsePlan, ValidationSuiteResult], IncidentReport]` |
| learning | `LearningRun` | `Callable[[], LearningPath]` |

`ScenarioCapabilities` carries one optional field per capability, typed to
these exact aliases. A capability a scenario does not implement is `None`.

A capability is chosen for the callable-alias type plus runtime result
assertions rather than `inspect.signature` reflection: the conformance
suite (see [scenario-conformance.md](scenario-conformance.md)) type-checks
the author's functions under strict mypy and asserts the result types at
runtime, which is a stronger and more readable guarantee than signature
inspection.

## Lifecycle dependency rules

The dependency model is about **capability input/result types**, not about
forcing sibling callables to call each other in a fixed order. Each
capability is independently implementable; a capability only requires the
*result type* of another capability when its own signature consumes it.

- **Simulation** — independent. Produces a `SimulationResult` with
  entities and events; requires no other capability.
- **Detection** — independent *when telemetry is supplied*. Consumes a
  sequence of events and emits `Finding` objects; it does not require
  simulation.
- **Investigation** — requires a `Finding` (the intermediate result of
  detection). An investigation without any way to produce a `Finding` is
  unsatisfiable.
- **Response** — requires an `InvestigationResult` (produced by
  investigation).
- **Validation** — independent at the registry-contract level; it consumes
  a `TelemetryArtefact`. That T1078's internal validation happens to rerun
  detection does **not** make detection a generic dependency of validation.
- **Reporting** — requires a `Finding`, an `InvestigationResult`, a
  `ResponsePlan`, and a `ValidationSuiteResult` (the four earlier
  intermediate results).
- **Learning** — independent. Produces a `LearningPath` from nothing.

So a scenario's declared capabilities are conformance-checked to be
*satisfiable*: if reporting is provided, detection, investigation, response,
and validation must all be present; if response is provided, investigation
must be present; and so on.

## A registration must be well-formed

A `ScenarioRegistration` requires:

- `technique_id` — the canonical MITRE ATT&CK ID (e.g. `T1078`);
- `slug` — a stable lowercase slug (e.g. `t1078_valid_accounts`);
- `name` — a display name;
- `metadata_loader` — a **lazy, named** callable returning a typed
  `duke.core.Scenario` (never a lambda);
- `aliases` — optional extra resolvable names;
- `capabilities` — a `ScenarioCapabilities` object.

Registration validation rejects empty core fields, empty or duplicate
aliases, and an alias that duplicates the scenario's own technique ID or
slug. The registry rejects cross-registration key collisions on any
normalized key.

## What a scenario author does not do

- **No conformance code in production** — there is no runtime
  `conformance.py` or `run_conformance()`; conformance is reusable pytest
  infrastructure under `tests/conformance/`.
- **No YAML requirement in the contract** — the generic metadata checks
  validate the `Scenario` returned by the `metadata_loader` directly. YAML
  agreement is a packaging concern verified per-scenario (T1078 asserts its
  YAML agreement separately).
- **No generic Markdown/report-export claims** — byte-level rendering and
  export guarantees are verified by the existing component tests, not by a
  generic conformance check.
- **No CLI changes** — registering a scenario and rebuilding the registry
  is enough; every command resolves and dispatches through the registry.

## Scenario versioning

Duke's **package version** and each scenario's **metadata/content version**
are **independent** and must not be conflated.

- The package version is the Duke release version (for example `0.2.0`
  on the `0.2.0` release branch, declared in `pyproject.toml` and surfaced
  by `duke version`).
- Each scenario carries its own `version` field in its metadata (for
  example `version: "0.1.0"` in `scenario.yaml`). That field describes the
  scenario's own metadata/content contract, not the Duke package release.

Consequences:

- A Duke package release does **not** automatically change scenario
  versions.
- A scenario version changes only when that scenario's documented
  metadata/content contract changes — for example, its entities, events,
  detection behaviour, safety model, or scenario metadata shape.
- A package release may leave every scenario version untouched.

This slice changes neither the Duke package version (still `0.1.0`) nor
either scenario's version (`t1078_valid_accounts` and
`t1110_brute_force` both remain `version: "0.1.0"`).

## Adding a scenario (summary)

1. Implement the scenario's capability functions in the appropriate
   `duke.*` packages, with the exact callable signatures above.
2. Provide a lazy named `metadata_loader` returning a typed `Scenario`.
3. Add a `ScenarioRegistration` in `duke.scenarios.builtins` wiring the
   capabilities (leaving unimplemented ones `None`).
4. Add the registration to `builtin_registry()`.
5. Add a conformance **fixture** (expectations) and register the scenario
   in the conformance pairs so the reusable checks run over it.

## References

- [scenario-conformance.md](scenario-conformance.md) — how conformance tests
  verify an authored scenario.
- [scenario-registry.md](scenario-registry.md) — the registry types and
  resolution semantics.
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — the contribution workflow.

Last reviewed: 2026-09-23
