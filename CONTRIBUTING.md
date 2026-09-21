# Contributing to Duke

Duke is a vendor-agnostic cybersecurity education and
security-engineering platform, developed in small, independently
testable vertical slices. Before contributing, read
[AGENTS.md](AGENTS.md) — it is the authoritative source for Duke's
principles, safety requirements, architecture, and documentation
policy. This guide summarizes the practical workflow.

## Getting started

See [docs/development/environment-setup.md](docs/development/environment-setup.md)
for a full walkthrough. In short:

```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Development principles

- Keep Duke's core vendor-agnostic; provider-specific behaviour
  belongs behind an adapter.
- Build the CLI before an API, TUI, or web interface.
- Use MITRE ATT&CK as a behavioural taxonomy, not a collection of
  attack scripts.
- Simulate adversary behaviour safely: reproduce observable telemetry
  rather than implementing offensive capability. Use synthetic data
  and isolated environments only.
- Use typed, readable Python.
- Keep components independently testable.
- Develop in small vertical slices; do not implement the entire
  roadmap or all ATT&CK tactics at once.
- Preserve clear boundaries between learning, simulation, telemetry,
  detection, investigation, response, validation, and reporting.
- Avoid unnecessary abstraction, and do not add empty or speculative
  modules ahead of need.

## Safety requirements

Duke must never implement destructive malware or ransomware,
credential theft, uncontrolled persistence, security-product
disabling, real data exfiltration, unauthorized access, uncontrolled
exploitation, or defense-evasion code. For sensitive ATT&CK
techniques, reproduce only their observable effects using synthetic
events, harmless files, temporary directories, and isolated lab
environments.

Every simulation must:

- explain what is being simulated
- state what is intentionally not implemented
- use synthetic or disposable data
- avoid modifying real security settings
- support safe cleanup where applicable
- be suitable for an authorized training environment

## Documentation policy

Documentation is mandatory: if we build it, we document it; if we
change it, we update its documentation in the same change. A feature
is not complete when its documentation is missing or outdated.
Depending on the change, this may include README.md, CHANGELOG.md,
ROADMAP.md, architecture documentation, development documentation,
lab documentation, detection/investigation/response/reporting
documentation, and Architecture Decision Records (see
[docs/decisions/](docs/decisions/)). Create a new ADR when a change
introduces a significant architectural decision.

## Testing and quality

New behaviour requires tests. Before submitting a change, run all of:

```bash
ruff check .
mypy src
pytest
```

See [docs/development/testing.md](docs/development/testing.md) for
details on the test layout and how to run a subset of tests.

## Submitting changes

- Keep pull requests scoped to a single vertical slice of
  functionality.
- Update documentation and the changelog in the same change.
- Ensure `ruff check .`, `mypy src`, and `pytest` all pass before
  requesting review.
