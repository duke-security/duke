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
- The `duke.validation` package: `ValidationStatus`, `ValidationCase`, and
  `ValidationSuiteResult` typed models for detection validation, with a
  read-only derived `all_passed` flag.
- Controlled, in-memory mutation helpers (`duke.validation.mutations`) that
  build new `TelemetryArtefact` values from immutable tuples and
  `model_copy` — never modifying the source artefact, never writing files,
  and cloning events with distinct deterministic IDs.
- Deterministic T1078 detection validation (`validate_t1078`) that consumes
  an existing `TelemetryArtefact`, reruns the detection → investigation →
  response-planning workflow against mutations, and reports 16 explicit
  cases (unmodified corpus, missing baseline, missing anchor, insufficient
  confidence, window expiry, wrong actor, duplicate non-inflation, five
  individual follow-on removals, benign activity, determinism, evidence
  traceability, and response-action safety).
- `duke validate T1078`: validates a supplied artefact and exits 0 when all
  cases pass, 1 for an invalid artefact or a failed suite, and 2 for an
  unsupported technique, without modifying the input file.
- Validation, mutation, result-model, and CLI tests covering every case,
  immutability of the source artefact and input-file bytes, determinism,
  exit codes, and a side-effect-free package guard.
- Validation documentation under `docs/validation/` and updated lab,
  README, roadmap, architecture, and changelog entries.
- The `duke.reporting` package: an `IncidentReport` typed content model
  aggregating the finding, involved entities, evidence, timeline, analysis,
  dry-run response plan, and validation suite, with a deterministic
  `report_id` and `generated_at` derived from the finding.
- Deterministic incident reporting (`report_t1078`) that consumes the
  existing telemetry artefact, finding, investigation result, response plan,
  and validation suite without regenerating telemetry, modifying the source,
  or executing responses.
- A deterministic Markdown renderer (`render_incident_report`) with escaped
  table content and a byte-identical, single-trailing-newline output.
- Safe report export (`export_report`) with overwrite protection and `--force`.
- `duke report T1078`: renders an advisory report and exits 0 on success (or
  for a benign artefact with "No findings to report" and no file), 1 for an
  invalid artefact, failed validation, unexpected finding count, existing
  output, or export failure, and 2 for an unsupported technique.
- Reporting report-model, renderer, export, end-to-end, and CLI tests covering
  determinism, cautious language, rollback rendering, table escaping, single
  validation run, unexpected-finding safety, and input immutability.
- Reporting documentation under `docs/reporting/` and updated README,
  roadmap, architecture, lab, investigation, response, validation, and
  changelog entries.
- The `duke.learning` package: typed, metadata-only guided-learning models
  (`LearningPath`, `LearningStep`, `LearningObjective`, `Exercise`, `Hint`,
  and `KnowledgeCheck`) with strict field validation, plus deterministic
  literal-pane rendering (`render_path`, `render_step`). The package never
  executes a command, writes or modifies a learner's files, grades work, or
  persists progress.
- A deterministic 11-step T1078 guided learning path (`t1078_learning_path`)
  that teaches Python through Duke's defensive T1078 workflow: orientation
  and safety, Python collections, typed models and validation, datetime
  arithmetic, functions and modules, detection reasoning, investigation,
  safe response, validation, reporting, and an end-to-end final challenge.
  Every lesson uses documented public exports and real CLI syntax (the
  documented confidence threshold is explained as a value, never via a
  private-constant import), guards with explicit safety notes, and labels
  knowledge-check answers as reference material for self-check.
- `duke learn T1078`: renders the path overview (exit 0), a single lesson by
  stable step id (`--step`, exit 0), and errors with exit 2 for an unknown
  step or an unsupported technique. Output is literal text, so code with
  brackets, dictionaries, and type annotations is never swallowed or
  reformatted by Rich.
- Guided-learning model, catalogue, renderer, and CLI tests covering stable
  step ids and ordering, lifecycle-stage coverage, complete lesson material,
  command examples using only implemented commands, concrete safety
  properties (no execution, file writes, grading, or persistence; dry-run,
  approval-gated response), deterministic construction and rendering, literal
  Rich-safe output, and exit codes.
- Guided-learning documentation under `docs/learning/` and updated README,
  roadmap, architecture, lab, testing, and changelog entries.
- The `duke.scenarios` package: a static built-in scenario registry. A typed,
  frozen `ScenarioRegistration` declares a technique ID, slug, name, aliases,
  a lazy metadata loader, and seven typed optional capabilities
  (`ScenarioCapabilities`) implemented as a `ScenarioCapability` StrEnum
  selection. The registry enforces non-empty core fields, unique normalized
  aliases, no alias matching the registration's own technique ID or slug, and
  no cross-registration key collisions.
- Case-insensitive resolution of scenarios by canonical technique ID, slug, or
  alias, preserving canonical display values, with clear
  `UnknownScenarioError` and `CapabilityMissingError` failures and a
  deterministic, lifecycle-ordered listing.
- The built-in registration (`duke.scenarios.builtins`) registering T1078 once
  with its lazy metadata loader and all seven capabilities, plus fresh
  `builtin_registry()` instances.
- `duke scenarios`: lists registered scenarios in deterministic technique-ID
  order with name, slug, capabilities (in lifecycle order), and aliases —
  without invoking any metadata loader or capability.
- CLI lifecycle commands (simulate, detect, investigate, respond, validate,
  report, learn) now resolve scenarios and dispatch to capabilities through
  the registry instead of hardcoding T1078 capability selection or technique
  checks; unknown scenarios and missing capabilities exit 2 before any
  capability executes.
- Scenario-registry, built-in-registry, import-order, and CLI tests covering
  registration validation, resolution, deterministic listing, lazy metadata,
  capability dispatch and absence, and fresh-process circular-import safety,
  plus the new CLI missing-capability exit-2 path.
- Scenario-registry documentation under `docs/scenarios/` and updated README,
  roadmap, architecture, testing, CONTRIBUTING, and changelog entries.


### Changed

- `Scenario.attack_tactic` was replaced by `attack_tactics` so one
  ATT&CK technique can map accurately to multiple tactics.
- CLI lifecycle commands no longer import or call T1078-specific capability
  functions directly; they resolve scenarios and dispatch to capabilities
  through the static built-in `duke.scenarios` registry (T1078 remains in help
  examples and default filenames).
