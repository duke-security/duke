# Changelog

All notable changes to Duke are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Duke adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Packaged YAML loading and validation for built-in Duke scenarios.
- Safe deterministic simulation for MITRE ATT&CK T1078 Valid Accounts,
  producing eight synthetic entities and eight normalized events.
- Structured JSON simulation artefacts with schema versioning,
  configurable output paths, and explicit overwrite protection.
- `duke simulate T1078` CLI command.
- T1078 lab documentation covering the scenario timeline, Python
  concepts, safety boundaries, artefact structure, and limitations.
- Automated tests for scenario loading, deterministic simulation,
  entity relationships, JSON export, file safety, and CLI behaviour.
- Vendor-neutral Pydantic v2 domain models for `SecurityEvent`,
  `Entity`, `Evidence`, `Finding`, `Incident`, `ResponseAction`, and
  `Scenario`.
- Strict validation for UUID relationships, timezone-aware timestamps,
  enum-controlled states, evidence provenance, incident composition,
  unknown fields, and response rollback requirements.
- Forty-nine focused core-model unit tests covering construction,
  validation, serialization, reconstruction, and relationships.
- Core domain-model architecture documentation with a normalized
  `SecurityEvent` example.
- Documentation foundation: README, ROADMAP, CONTRIBUTING, and
  architecture/development documentation describing Duke's current
  capabilities and planned components.
- Architecture Decision Records for a vendor-agnostic core
  (ADR 0001), a CLI-first interface (ADR 0002), and safe synthetic
  simulations (ADR 0003).
- Installable Python package (`duke-security`) with a Typer/Rich
  command-line interface.
- `duke --help` and `duke version` commands.
- CLI unit tests.
- Ruff, mypy (strict), and pytest quality gates.


### Changed

- `Scenario.attack_tactic` was replaced by `attack_tactics` so one
  ATT&CK technique can map accurately to multiple tactics.
