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
- CLI unit tests
- Quality gates: [Ruff](https://docs.astral.sh/ruff/), mypy (strict), pytest

### Planned

The core domain model and the T1078 scenario’s metadata, simulation,
normalized telemetry, JSON export, CLI commands, and behaviour-based
detection are implemented.
Evidence-led investigation, safe response, detection validation,
incident reporting, learning exercises, additional scenarios, and
vendor adapters remain **planned**.

See [the T1078 lab documentation](docs/labs/T1078/overview.md),
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
duke detect T1078 --input data/events/t1078-session-001.json
```

## Documentation

- [ROADMAP.md](ROADMAP.md) — what's built, what's planned, and in what order
- [CHANGELOG.md](CHANGELOG.md) — release history
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [docs/architecture/overview.md](docs/architecture/overview.md) — component architecture
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
