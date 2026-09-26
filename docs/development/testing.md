# Testing

Duke requires tests for all new behaviour, and all quality checks
must pass before a change is considered complete.

## Prerequisites

Install development dependencies first — see
[environment-setup.md](environment-setup.md):

```bash
pip install -e ".[dev]"
```

## Required checks

Run all three before submitting a change, in this order:

```bash
ruff check .
mypy src
pytest
```

- **Ruff** lints the codebase (`E`, `F`, `I`, `B`, `UP` rule sets, 88
  character line length).
- **mypy** type-checks the `duke` package in strict mode. The reusable
  scenario-conformance code under `tests/conformance/` is also
  type-checked in strict mode, including its independent probe callables:

  ```bash
  mypy src tests/conformance
  ```

  The thin pytest *drivers* in that package are exempt from the untyped-def
  and typed-context rules via a `pyproject.toml` override, so existing test
  conventions do not have to be migrated; the helpers, fixtures, and probe
  callables they exercise remain fully strict-checked.
- **pytest** runs the test suite.

## Test layout

Tests live under `tests/`, mirroring the structure of `src/duke`.
Unit tests for the CLI are in `tests/unit/test_cli.py`, built with
Typer's `CliRunner`. Response-planning and plan-model tests live under
`tests/unit/response/`; detection-validation, mutation, and validation
result-model tests live under `tests/unit/validation/`; incident-reporting
report-model, renderer, export, and end-to-end tests live under
`tests/unit/reporting/`; guided-learning model, catalogue, and rendering
tests live under `tests/unit/learning/`; scenario-registry tests live
under `tests/unit/scenarios/`.

```bash
pytest tests/unit/test_cli.py
pytest tests/unit/response
pytest tests/unit/validation
pytest tests/unit/reporting
pytest tests/unit/learning
pytest tests/unit/scenarios
pytest tests/conformance
```

### Scenario conformance

Reusable, **test-only** conformance infrastructure lives under
`tests/conformance/` and validates that every registered scenario satisfies
the same authoring contract — see
[docs/scenarios/scenario-conformance.md](../scenarios/scenario-conformance.md).
It is scenario-independent: the same `checks.py` verifies both the built-in
T1078 scenario and an independent `probe.py` scenario, and an AST-based
import guard in `test_production.py` proves the reusable sources never
import a `duke.*.t1078` implementation module.

The second built-in scenario, T1110 (simulation + detection, modelling
T1110.003 Password Spraying), is covered by the **generic** conformance
checks (metadata, registration, registry, simulation, artefact,
relationships, and — now that detection is provided — the deterministic
detection check) directly in `test_production.py`. Because it does not yet
provide the full lifecycle, it is deliberately **not** added to the
full-lifecycle `SCENARIO_PAIRS`; the later-lifecycle conformance checks
(response, validation, reporting, learning) correctly report passing
"not declared" skips for it.

The scenario-registry tests (`tests/unit/scenarios/`) cover the typed
registry model — registration validation, case-insensitive resolution by
technique ID, slug, and alias, duplicate/collision errors, deterministic
listing in lifecycle capability order, capability presence and dispatch,
and lazy metadata loading with no capability invocation. Separate
import-order tests launch fresh Python subprocesses to verify that
`duke.cli.app` and `duke.scenarios.builtins` import in either order without
circular-import failures (bypassing any in-process import cache).


## Coverage

`pytest-cov` is available as a development dependency, with coverage
configuration (source `duke`, branch coverage) already defined in
`pyproject.toml`. To generate a coverage report:

```bash
pytest --cov=duke --cov-report=term-missing
```

## Adding tests

New components (simulation, telemetry, detection, investigation,
response, reporting, learning, labs, adapters) must ship with their own
tests as they are implemented, keeping each layer independently testable.
Guided-learning tests verify stable step ids and ordering, coverage of
every lifecycle stage, complete lesson material, that command examples use
only implemented CLI commands, concrete safety-property assertions (no
execution, file writes, grading, or persistence; dry-run/approval-gated
response), deterministic construction and rendering, and literal
Rich-safe output so bracket-heavy code is never swallowed.
