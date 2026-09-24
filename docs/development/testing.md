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
- **mypy** type-checks the `duke` package in strict mode.
- **pytest** runs the test suite.

## Test layout

Tests live under `tests/`, mirroring the structure of `src/duke`.
Unit tests for the CLI are in `tests/unit/test_cli.py`, built with
Typer's `CliRunner`. Response-planning and plan-model tests live under
`tests/unit/response/`; detection-validation, mutation, and validation
result-model tests live under `tests/unit/validation/`.

```bash
pytest tests/unit/test_cli.py
pytest tests/unit/response
pytest tests/unit/validation
```

## Coverage

`pytest-cov` is available as a development dependency, with coverage
configuration (source `duke`, branch coverage) already defined in
`pyproject.toml`. To generate a coverage report:

```bash
pytest --cov=duke --cov-report=term-missing
```

## Adding tests

New components (simulation, telemetry, detection, investigation,
response, reporting, labs, adapters) must ship with their own tests
as they are implemented, keeping each layer independently testable.
