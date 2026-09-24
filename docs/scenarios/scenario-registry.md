# Scenario Registry

## Status

A **static, built-in scenario registry** is implemented. The CLI resolves
scenarios and dispatches capabilities through the registry instead of
hardcoding T1078 technique checks. This is **not** a dynamic plugin system.

## What it is

The scenario registry is a typed, in-code collection of scenario
registrations. Each registration pairs scenario metadata with the callable
capabilities that implement that scenario across Duke's lifecycle:
simulation, detection, investigation, response, validation, reporting, and
learning.

Its two responsibilities are deliberately narrow:

- it **selects metadata and capability callables** for a resolved scenario;
- it **rejects duplicate or malformed registrations** and resolves keys
  case-insensitively.

The CLI remains responsible for options, input/output paths, exit codes,
and console presentation. Telemetry loading, simulation export, and report
writing stay in their existing packages; the registry only wires the
scenario-specific callables.

## Why a static registry (not plugins)

Duke's registry is **static and built-in**: the set of registered scenarios
is determined at build/import time from code in
`duke.scenarios.builtins`, not discovered from disk, entry points, or
third-party packages. There is:

- no plugin system or entry-point discovery;
- no dynamic third-party loading;
- no configuration database;
- no runtime discovery of scenario packages.

A future scenario is added by editing `duke.scenarios.builtins` (and
packaging its YAML + capability modules), never by adapting the CLI or the
registry itself.

## Module layout

- `src/duke/scenarios/registry.py` — registry types, errors, and logic.
  Imports only `duke.core` and the capability *result* types (none of which
  import `duke.scenarios`), so it cannot participate in a circular import.
- `src/duke/scenarios/builtins.py` — the **composition root**. The only
  module that imports the concrete capability callables (e.g.
  `generate_t1078_simulation`, `detect_t1078`) and wires them into
  `ScenarioCapabilities`.
- `src/duke/scenarios/__init__.py` — re-exports the registry types and
  errors. It deliberately does **not** import `builtins`.

### Why `builtins` is imported only from the CLI

Capability modules (notably `duke.simulation.t1078`) import from
`duke.scenarios` for the packaged metadata loader. If
`duke.scenarios/__init__.py` eagerly imported `builtins`, we would create a
cycle: `duke.scenarios.builtins -> duke.simulation -> duke.simulation.t1078
-> duke.scenarios`. Keeping `builtins` imported only from the CLI (and
tests) breaks that cycle. Fresh-process import-order tests
(`tests/unit/scenarios/test_import_order.py`) guard both import orders.

## Types

### `ScenarioCapability` (StrEnum)

The lifecycle capabilities, in canonical lifecycle order:

`simulation`, `detection`, `investigation`, `response`, `validation`,
`reporting`, `learning`.

### `ScenarioCapabilities` (frozen dataclass)

Explicitly typed optional fields, one per capability, typed to the exact
public callable signatures (e.g. `SimulationRun`, `DetectRun`,
`InvestigateRun`, `ResponsePlanRun`, `ValidationRun`, `ReportRun`,
`LearningRun`). A scenario that does not implement a capability leaves that
field `None`.

### `ScenarioRegistration` (frozen dataclass)

```
technique_id: str            # canonical ATT&CK ID, e.g. "T1078"
slug: str                    # stable slug, e.g. "t1078_valid_accounts"
name: str                    # display name
aliases: tuple[str, ...]     # extra resolvable names
capabilities: ScenarioCapabilities
metadata_loader: Callable[[], Scenario]   # lazy, named function (never a lambda)
```

Validation rejects: empty `technique_id`/`slug`/`name`; duplicate (or empty)
aliases; an alias duplicating its own technique ID or slug. Lookup is
case-insensitive but canonical display values (e.g. `T1078`) are preserved.

### Errors

- `UnknownScenarioError` — a key resolves to no registered scenario.
- `CapabilityMissingError` — a scenario lacks a requested capability.
- `DuplicateScenarioError` — a registration collides on a normalized key
  (technique ID, slug, or alias) with an already registered one.
- `ScenarioRegistrationError` — a registration fails its own metadata
  validation.

All subclass `ScenarioRegistryError`.

## Resolution and duplication

`ScenarioRegistry.resolve(key)` folds the key to lowercase and looks it up
against each registration's technique ID, slug, and aliases. The built-in
T1078 registration resolves all of these to the same registration:

- `T1078` / `t1078` (technique ID, case-insensitive)
- `t1078_valid_accounts` (stable slug)
- `valid-accounts` (alias)

`register()` builds each registration's normalized key set and rejects any
collision with an already registered scenario, so duplicate canonical IDs,
duplicate slugs, and alias collisions are all caught.

The registry **never executes a capability** during registration, listing,
or resolution — it only stores and returns callable references.

## Capability-aware dispatch

`required_capability(registration, ScenarioCapability)` returns a scenario's
capability callable or raises `CapabilityMissingError`. Commands resolve the
scenario through the registry, then fetch each capability they need. A
future registered scenario that lacks a requested capability therefore fails
clearly (exit code 2) instead of crashing or silently misbehaving.

## Extension procedure: adding a scenario

To add a new scenario (e.g. `T9999`):

1. **Package its metadata** — create `src/duke/scenarios/<slug>/scenario.yaml`
   and implement its capability modules (simulation, detection, etc.) in the
   appropriate `duke.*` packages.
2. **Build a registration** — add a `t9999_registration()` function in
   `src/duke/scenarios/builtins.py` that sets `technique_id`, `slug`, `name`,
   `aliases`, a lazy named `metadata_loader`, and a `ScenarioCapabilities`
   populated from that scenario's public functions (leave unimplemented
   capabilities `None`).
3. **Register it** — add `registry.register(t9999_registration())` to
   `builtin_registry()`.
4. **Do not touch the CLI** — `duke scenarios`, resolution, and every
   command pick the scenario up automatically through the registry.

## Deterministic listing

- scenarios are listed sorted by canonical technique ID (then slug);
- capabilities are shown in lifecycle order;
- aliases are shown in their stable tuple order.

## References

- [Architecture overview](../architecture/overview.md)
- [ROADMAP.md](../../ROADMAP.md)
- [T1078 guided learning path](../learning/T1078-guided-learning.md)
- [CONTRIBUTING.md](../../CONTRIBUTING.md)

Last reviewed: 2026-09-23
