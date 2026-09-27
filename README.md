# Duke

Duke is a vendor-agnostic, interactive cybersecurity education and
security-engineering platform. It teaches Python through realistic,
safe security workflows instead of toy exercises, walking learners
through the full lifecycle a security engineer lives day to day:

```
Learn → Simulate → Observe → Detect → Investigate → Respond →
Validate → Document → Improve → Retest
```

This lifecycle is continuous: improvements are retested to confirm
that detections, controls, and response processes actually work.

Duke's core is intentionally vendor-neutral. Cloud- and
vendor-specific integrations (a particular SIEM, EDR, or cloud
provider) live behind adapters, never inside the core domain model.
See [ADR 0001](docs/decisions/0001-vendor-agnostic-core.md).

## Project status

Duke is under active early development. The first milestone is a
single, complete, end-to-end scenario based on MITRE ATT&CK
**T1078 — Valid Accounts**. T1078 is the first vertical slice used to
prove out the platform's architecture, not the only scenario Duke
will ever support — see [ROADMAP.md](ROADMAP.md).

### Implemented today

- An installable Python package (`duke-security`)
- Packaged and validated YAML scenario definitions
- A deterministic, safe T1078 Valid Accounts simulation containing
  eight synthetic entities and eight normalized events
- Structured JSON artefact export with overwrite protection
- `duke simulate T1078`
- Vendor-neutral Pydantic v2 domain models for security events,
  entities, evidence, findings, incidents, response actions, and scenarios
- A [Typer](https://typer.tiangolo.com/)/[Rich](https://rich.readthedocs.io/)
  command-line interface
- `duke --help`
- `duke version`
- `duke detect T1078`
- Behaviour-based detection for the T1078 scenario, using an explainable
  weighted confidence score to emit vendor-neutral findings
- `duke investigate T1078`
- Evidence-led investigation of an existing finding, producing a
  chronological timeline, per-event evidence, involved entities, confirmed
  facts, analyst assessments, and unresolved questions
- `duke respond T1078`
- Dry-run-only response planning that correlates a finding into a
  preliminary incident and proposes approval-gated actions grouped into
  containment, evidence preservation, investigation follow-up, and
  recovery — never modifying a real system
- `duke validate T1078`
- Deterministic detection validation that reruns the detection →
  investigation → response pipeline against controlled in-memory
  mutations of the artefact (which is never modified), reporting pass/fail
  per case
- `duke report T1078`
- Deterministic, advisory incident reporting that aggregates the finding,
  investigation, dry-run response plan, and validation suite into a
  Markdown report — never asserting confirmed compromise, impact, or
  exfiltration, and never executing an action
- `duke learn T1078`
- A T1078 guided learning path: an 11-step, deterministic, beginner-friendly
  walk that teaches Python through Duke's defensive T1078 workflow. Each
  step reuses real CLI commands and public exports as metadata — it never
  executes a command, modifies learner files, grades, or persists progress
- `duke scenarios`
- A static, built-in scenario registry: scenarios are registered once with
  their metadata and lifecycle capability callables (simulation, detection,
  investigation, response, validation, reporting, learning), resolved
  case-insensitively by technique/slug/alias, and dispatched by the CLI
  through the registry rather than through hardcoded technique checks
- A second production scenario, **T1110 — Brute Force** (`duke simulate
  T1110`), currently a **simulation, detection, investigation, response, and
  validation slice**: it models the observable telemetry of ATT&CK
  sub-technique **T1110.003 Password Spraying** — a benign baseline
  authentication, six evenly-spaced failed authentications against distinct
  accounts from a single external source, and one later success — without
  performing real authentication or implying compromise. `duke detect T1110`
  identifies the spray pattern as a behaviour-based finding: a deterministic
  sliding-window rule requires at least five distinct accounts failed from one
  source within 30 minutes, credits a later success only as supporting
  evidence, and never assumes compromise. `duke investigate T1110` turns that
  finding into an evidence-led timeline, cautious confirmed facts, and
  unresolved questions, without ever claiming compromise or attribution.
  `duke respond T1110` proposes a dry-run-only, approval-gated response plan
  whose evidence-led targets the source and a verified success-associated
  account, is conditional and proportionate, and never executes anything.
  `duke validate T1110` proves the whole pipeline with an ordered 19-case
  deterministic validation suite (19/19 passing on the canonical corpus),
  never mutating the source artefact or input file. The remaining T1110
  lifecycle commands (report/learn) still fail safely with exit code 2 through
  the registry's missing-capability path.
- Reusable, test-only scenario-conformance infrastructure: the same
  checks validate both the built-in T1078 scenario and an independent
  probe scenario, with an AST guard proving the conformance sources stay
  independent of the T1078 implementation modules
- CLI unit tests
- Quality gates: [Ruff](https://docs.astral.sh/ruff/), mypy (strict), pytest

### Planned

The core domain model and the T1078 scenario’s metadata, simulation,
normalized telemetry, JSON export, CLI commands, behaviour-based
detection, evidence-led investigation, safe dry-run response,
deterministic detection validation, deterministic incident reporting, a
T1078 guided learning path, and a static scenario registry are
implemented. The T1110 scenario currently provides simulation, detection,
investigation, response, and validation; its reporting and learning
capabilities are **planned**. The full learning component (additional scenarios and their
learning paths, learner-progress tracking, broader improve → retest
learning workflows, further lesson content), a dynamic/plugin scenario
registry, additional ATT&CK scenarios, and vendor adapters remain
**planned**.

See [the T1078 guided learning guide](docs/learning/T1078-guided-learning.md),
[the T1078 lab documentation](docs/labs/T1078/overview.md),
[the T1110 lab documentation](docs/labs/T1110/overview.md),
[the architecture overview](docs/architecture/overview.md), and
[ROADMAP.md](ROADMAP.md) for details.

## Installation

Duke requires Python 3.11 or later.

```bash
pip install duke-security
```

For local development, install it in editable mode instead — see
[docs/development/environment-setup.md](docs/development/environment-setup.md).

## Usage

```bash
duke --help
duke version
duke simulate T1078
duke simulate T1110 --output data/events/t1110-session-001.json
duke detect T1078 --input data/events/t1078-session-001.json
duke detect T1110 --input data/events/t1110-session-001.json
duke investigate T1078 --input data/events/t1078-session-001.json
duke investigate T1110 --input data/events/t1110-session-001.json
duke respond T1078 --input data/events/t1078-session-001.json
duke respond T1110 --input data/events/t1110-session-001.json
duke validate T1078 --input data/events/t1078-session-001.json
duke validate T1110 --input data/events/t1110-session-001.json
duke report T1078 \
  --input data/events/t1078-session-001.json \
  --output reports/t1078-incident-report.md
duke learn T1078
duke learn T1078 --step detection
duke scenarios
```

## Documentation

- [ROADMAP.md](ROADMAP.md) — what's built, what's planned, and in what order
- [CHANGELOG.md](CHANGELOG.md) — release history
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [docs/architecture/overview.md](docs/architecture/overview.md) — component architecture
- [docs/scenarios/scenario-registry.md](docs/scenarios/scenario-registry.md) — the scenario registry and how to add a scenario
- [docs/scenarios/scenario-authoring.md](docs/scenarios/scenario-authoring.md) — the authoring contract for a new scenario
- [docs/scenarios/scenario-conformance.md](docs/scenarios/scenario-conformance.md) — scenario conformance checks
- [docs/labs/T1078/overview.md](docs/labs/T1078/overview.md) — the T1078 lab
- [docs/labs/T1110/overview.md](docs/labs/T1110/overview.md) — the T1110 simulation/detection/investigation/response/validation lab
- [docs/investigations/T1110-password-spraying.md](docs/investigations/T1110-password-spraying.md) — the T1110 investigation
- [docs/responses/T1110-safe-response.md](docs/responses/T1110-safe-response.md) — the T1110 response plan
- [docs/validation/T1110-detection-validation.md](docs/validation/T1110-detection-validation.md) — the T1110 validation suite
- [docs/learning/T1078-guided-learning.md](docs/learning/T1078-guided-learning.md) — the guided learning path
- [docs/development/environment-setup.md](docs/development/environment-setup.md) — local setup
- [docs/development/testing.md](docs/development/testing.md) — running the test suite
- [docs/decisions/](docs/decisions/) — Architecture Decision Records

## Safety

Duke reproduces the *observable effects* of adversary behaviour using
synthetic data, harmless files, and isolated environments. It never
implements destructive malware, credential theft, real data
exfiltration, unauthorized access, or defense evasion. Every
simulation states what it does and does not do. See
[AGENTS.md](AGENTS.md) for the full safety policy.

## License

License to be determined.
