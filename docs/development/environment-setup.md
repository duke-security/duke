# Environment Setup

This guide covers setting up a local development environment for
Duke.

## Prerequisites

- Python 3.11 or later
- `pip`

## Clone and create a virtual environment

```bash
git clone <repository-url>
cd duke

python -m venv .venv
```

Activate the virtual environment:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

## Install Duke in editable mode

Install the package with its development dependencies (mypy,
pre-commit, pytest, pytest-cov, and Ruff):

```bash
pip install -e ".[dev]"
```

Editable mode means changes to the source under `src/duke` take
effect immediately without reinstalling.

## Verify the installation

```bash
duke --help
duke version
```

`duke --help` should describe Duke's purpose, and `duke version`
should print the installed package version.

## Next steps

- See [testing.md](testing.md) for running the test suite and
  quality checks.
- See [../architecture/overview.md](../architecture/overview.md) for
  how the codebase is organized.
- See [../../CONTRIBUTING.md](../../CONTRIBUTING.md) for the
  contribution workflow.
