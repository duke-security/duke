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
- `Finding.confidence`: an integer `0`–`100` scoring how strongly a
  detection asserts a finding, with boundary validation and unit tests.
- Deterministic, behaviour-based detection for T1078 Valid Accounts.
  An explainable weighted score requires a known-good baseline login
  and a later login from a new network and unfamiliar device, then
  correlates distinct follow-on behaviours within 15 minutes to emit a
  `Finding` (new-context login 25 points; repository enumeration 10,
  restricted file access 15, privileged-access request 15, archive
  creation 10, and network egress 15). Findings are produced only at a
  confidence of 60 or more, and confidence derives severity (medium or
  high, never critical).
- `duke detect T1078`, which loads and validates a normalized telemetry
  JSON artefact (`--input`) and reports findings; it never silently
  regenerates the simulation.
- Detection input loading with clear, non-zero error handling for
  missing files, directories, malformed JSON, unsupported schema
  versions, and invalid `SecurityEvent` records, plus automated tests.
- Detection unit tests covering true positives, benign activity,
  insufficient score, correlation-window expiry, missing baseline,
  wrong actor, duplicate behaviours, deterministic output, confidence
  range, and event/entity relationships.
- Telemetry artefact ingestion in `duke.telemetry` (`load_telemetry_artefact`
  and `load_events`), loading normalized `Entity` and `SecurityEvent`
  collections from exported JSON with clear error handling. `duke.detection`
  re-exports `load_events`/`EventLoadError` for backwards compatibility.
- `InvestigationResult` and `TimelineEntry` typed models, plus the
  `duke.investigation` package.
- Evidence-led T1078 investigation (`investigate_t1078`) that consumes an
  existing `Finding` and builds a chronological timeline, one `Evidence`
  per referenced event (known-good baseline as `PROVIDES_CONTEXT`,
  new-context authentication and follow-ons as `SUPPORTS`), the involved
  entities, and distinct confirmed facts, analyst assessments, and
  unresolved questions.
- `duke investigate T1078`: loads an exported artefact, runs detection,
  and either reports no findings (exit 0) or prints the evidence-led
  investigation for each finding. Invalid artefacts exit 1; unsupported
  techniques exit 2.
- Investigation, loader, and CLI tests covering evidence creation,
  relationship classification, chronological timelines, entity resolution,
  deterministic output, benign handling, and exit codes.
- The `duke.response` package: `ResponseCategory`, `ResponseActionGroup`,
  and `ResponsePlan` typed models for dry-run-only response planning.
- Dry-run T1078 response planning (`plan_t1078_response`) that consumes an
  existing artefact and `InvestigationResult`, correlates the finding into
  a deterministic preliminary `Incident` (recorded so each action can carry
  an `incident_id`, without asserting compromise or exfiltration), and
  proposes approval-gated actions grouped into containment, evidence
  preservation, investigation follow-up, and recovery.
- Conservative rollback semantics for the proposed actions: revoked
  sessions and rotated credentials are not restorable, preserved evidence
  is never deleted as rollback, review-only actions carry no rollback,
  and MFA rollback never weakens baseline requirements.
- `duke respond T1078`: proposes a dry-run plan from an exported artefact,
  reporting no findings (exit 0) when detection finds nothing, invalid
  artefacts (exit 1), and unsupported techniques (exit 2). No real
  account, session, permission, file, network, or security control is
  modified.
- Response planner, plan-model, and CLI tests covering category ordering,
  dry-run/approval/planned guarantees, rollback classifications,
  conditional non-asserting wording, determinism, incident correlation,
  side-effect freedom, benign handling, and exit codes.
- Response documentation under `docs/responses/` and updated lab,
  investigation, README, roadmap, architecture, and changelog entries.


### Changed

- `Scenario.attack_tactic` was replaced by `attack_tactics` so one
  ATT&CK technique can map accurately to multiple tactics.
