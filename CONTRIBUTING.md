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
mypy src tests/conformance
pytest
```

See [docs/development/testing.md](docs/development/testing.md) for
details on the test layout and how to run a subset of tests.

## Registering a new scenario

Scenarios are added in one place — the static built-in registry
(`duke.scenarios.builtins`) — rather than by editing every CLI command.
The CLI resolves scenarios and dispatches to capabilities exclusively
through the registry.

To add a scenario:

1. Implement the scenario metadata (a `scenario.yaml` plus a loader
   returning a typed `Scenario`) and whichever of the seven capabilities
   the scenario supports (simulation, detection, investigation, response,
   validation, reporting, learning), with matching typed callable
   signatures.
2. Add a `ScenarioRegistration` in `duke.scenarios.builtins` — a technique
   ID, slug, name, aliases, the metadata loader, and a
   `ScenarioCapabilities` object listing the supported capabilities.
3. Register it in `builtin_registry()`. The registry enforces unique
   technique IDs, slugs, and aliases, and rejects a registration that
   duplicates its own ID or slug.
4. No CLI changes are required. Commands that need a capability your
   scenario does not provide fail clearly with exit code 2. The
   `duke scenarios` command lists it automatically, in deterministic
   technique-ID order.

Because the registry is static and built-in (not a dynamic plugin or
filesystem discovery), each scenario is a small, testable, documented
vertical slice. Add registration, capability, and CLI tests alongside it.

New scenarios should also add conformance expectations: declare the
scenario's expected entity/event/finding counts and technique in
`tests/conformance/builtin_pairs.py` so the reusable, scenario-independent
conformance checks (see [scenario-conformance.md](docs/scenarios/scenario-conformance.md))
run over it too. Do not add conformance code to the production `duke`
package — conformance lives entirely under `tests/`.

## Submitting changes

- Keep pull requests scoped to a single vertical slice of
  functionality.
- Update documentation and the changelog in the same change.
- Ensure `ruff check .`, `mypy src`, and `pytest` all pass before
  requesting review.
