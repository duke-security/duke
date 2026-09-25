# Scenario Conformance

Duke validates that every registered scenario meets the same authoring
contract using **reusable, test-only conformance infrastructure**. There is
no production conformance runner: all of this lives under
`tests/conformance/` and runs with pytest. The infrastructure is
scenario-independent — it never imports a T1078 implementation module — so
the same checks verify both the built-in T1078 scenario and an independent
probe scenario, proving the checks themselves are reusable.

## The four separated conformance areas

1. **Declaration conformance** — a registration's capability callables are
   the exact aliases, resolve through
   `has_capability`/`required_capability`, and each run returns its
   documented result type.
2. **Isolated registry conformance** — resolution by canonical/slug/alias,
   deterministic ordering, and duplicate rejection, exercised over an
   isolated `ScenarioRegistry` populated with both T1078 and the probe.
3. **Behavioural conformance** — determinism of simulation and detection,
   artefact validity (unique entity/event IDs, resolved relationships),
   safe-response guarantees, and validation/reporting/learning determinism.
4. **Production built-in / CLI conformance** — `builtin_registry()` still
   contains exactly T1078, CLI resolution agrees, T1078's YAML agreement is
   asserted here only, and an AST-based guard proves the reusable sources
   stay independent of the T1078 implementation modules.

## Key files

| Path | Purpose |
|---|---|
| `tests/conformance/__init__.py` | Marks the package test-only. |
| `tests/conformance/fixture.py` | `ScenarioConformanceFixture` — canonical inputs + expectations for one scenario. |
| `tests/conformance/checks.py` | The reusable `check_*` functions (metadata, declaration, dependencies, registry, simulation, artefact, relationships, detection, safe response, validation, reporting, learning). |
| `tests/conformance/probe.py` | A full independent probe scenario (T9999) with its own namespace and no T1078 imports. |
| `tests/conformance/builtin_pairs.py` | The scenario/expectation pairs under conformance (T1078 + probe) with a typed `ScenarioExpectations`. |
| `tests/conformance/test_declaration.py` | Declaration conformance for every scenario. |
| `tests/conformance/test_registry.py` | Isolated registry conformance. |
| `tests/conformance/test_behavioural.py` | Behavioural conformance plus the negative tests. |
| `tests/conformance/test_production.py` | Production built-in/CLI conformance and the AST import guard. |

`fixture.py`, `checks.py`, and `probe.py` are the reusable,
implementation-independent core. `builtin_pairs.py` is the one place that
composes in the production T1078 built-in (the intended composition point).

## The ScenarioConformanceFixture

A fixture binds a `ScenarioRegistration` to the concrete data behavioural
checks need:

- the `Scenario` returned by its lazy `metadata_loader`;
- a canonical `TelemetryArtefact` derived by running its simulation once;
- explicit, author-declared expectations: expected entity/event/finding
  counts and the expected finding technique.

Expectations are supplied by the caller and never hardcoded to a technique,
so the same fixture type serves any scenario.

## Scoring: named invariants

Every `check_*` function returns a tuple of `ConformanceCheck` objects, each
carrying a `name`, a `passed` flag, and a `detail`. Positive tests assert
every check passes. Negative tests build deliberately broken scenarios and
assert that the **specific** invariant violated is reported as failing — so
a future scenario that breaks a rule fails for the right reason.

## Negative tests prove the invariants are real

`tests/conformance/test_behavioural.py` includes negative cases that each
violate exactly one invariant and assert that invariant fails:

- duplicate entity IDs → `artefact.unique_entity_ids`
- duplicate event IDs → `artefact.unique_event_ids`
- event referencing a missing actor/target entity →
  `relationship.event_references`
- finding referencing a missing event/entity →
  `relationship.finding_references`
- nondeterministic simulation → `simulation.deterministic`
- nondeterministic detection → `detection.deterministic`
- a provided response containing a non-dry-run action →
  `response.actions_dry_run`
- a response action not requiring approval →
  `response.actions_require_approval`
- a response action status not `PLANNED` → `response.actions_planned`
- unsatisfied downstream fixture inputs / capability dependencies →
  `dependency.*`

Each negative case constructs a broken capability (for example, a patched
response whose plan contains a non-dry-run action) and asserts the exact
check that should fail.

## Independence from T1078

The reusable sources (`fixture.py`, `checks.py`, `probe.py`) must not import
any `duke.*.t1078` implementation module. `test_production.py` enforces this
with an **AST-based import guard**: it parses each reusable source with the
`ast` module and rejects imports from `duke.simulation.t1078`,
`duke.detection.t1078`, `duke.investigation.t1078`, `duke.response.t1078`,
`duke.validation.t1078`, `duke.reporting.t1078`, and `duke.learning.t1078`.
Because it inspects the module tree rather than substrings, a comment that
merely mentions `t1078` cannot trip the guard. A second guard test checks
that each forbidden name corresponds to a real implementation module, so
the list cannot silently drift out of date.

## Metadata checks are generic; YAML stays per-scenario

The generic metadata checks validate the `Scenario` returned by the
`metadata_loader` — they do **not** require YAML. Agreement between that
`Scenario` and its `ScenarioRegistration` is checked where fields
correspond, and the slug/aliases are validated independently. Only the
T1078 production conformance test asserts agreement with its YAML
definition.

## Running conformance

```bash
pytest tests/conformance -q
```

The reusable helpers, fixture, and probe callables are also checked under
strict mypy:

```bash
mypy src tests/conformance
```

## References

- [scenario-authoring.md](scenario-authoring.md) — the contract these
  checks validate.
- [scenario-registry.md](scenario-registry.md) — registry types and
  resolution.
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — the contribution workflow.

Last reviewed: 2026-09-23
