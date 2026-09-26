# Changelog

All notable changes to Duke are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Duke adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- A second production scenario, MITRE ATT&CK **T1110 — Brute Force**
  (`duke simulate T1110`), implemented as a **simulation slice only**.
  It reproducibly models the observable telemetry of sub-technique
  **T1110.003 Password Spraying**: a benign baseline authentication at a
  fixed time, six evenly-spaced (2-minute) failed authentications against
  six distinct accounts from a single external source beginning 12 hours
  later, and one successful authentication against a previously targeted
  account 12 minutes after spraying begins. The simulation never performs
  real authentication, stores or implies a credential value (only the
  observable `failure_reason="invalid_credentials"` label appears), uses
  documentation-range RFC 5737 IP addresses, and never labels any account
  as compromised or any actor as an attacker. T1110 is registered with
  canonical (`T1110`), slug (`t1110_brute_force`), friendly (`brute-force`),
  and sub-technique (`T1110.003`) resolution keys and provides **simulation
  only**; unsupported lifecycle commands (`detect`, `investigate`, `respond`,
  `validate`, `report`, `learn`) fail safely with exit code 2 through the
  registry's missing-capability path. The simulation-only scenario passes
  the generic scenario-conformance checks (metadata, registration, registry,
  simulation, artefact, relationships) and round-trips through the existing
  telemetry loader with no schema change. Detection, investigation,
  response, validation, reporting, and learning for T1110 are intentionally
  not yet implemented. Includes simulation, registry, CLI, determinism,
  safety (no credential material, documentation-safe IPs, no side-effecting
  generation), artefact round-trip, and documentation tests.
- Deterministic, explainable **T1110 detection** (`duke detect T1110`) for
  the T1110.003 password-spraying simulation (`password-spraying-window`).
  It groups events by source actor and evaluates a sliding 30-minute
  correlation window, selecting the best qualifying window by greatest
  distinct-account count, then failure count, then earliest start, then
  event-ID ordering. The hard gate requires at least five distinct accounts
  failed from a single source within the window; a shared service target
  (present in every failure) never counts as an account, and repeated
  failures against one account never inflate the count. Confidence starts at
  a base of 60 (so a bare spray is still reported), gains points for distinct
  accounts beyond the threshold (capped), and gains a 15-point bonus only
  when the same source later authenticates, strictly after the account's
  failure and no later than the window end, to a previously-failed account —
  credited strictly as **supporting evidence**, never as proof of compromise.
  Severity derives from confidence (medium or high, never critical); the
  finding explicitly states that compromise is not confirmed. event_ids trace
  every in-window failed authentication (including repeats) plus any credited
  success; entity_ids implicate only the source and the distinct sprayed
  accounts (the shared service stays contextual). Includes unit, CLI,
  malformed-input, threshold/window-boundary, mixed-source, determinism,
  attribution, and conformance tests.
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
- Reusable, test-only scenario-conformance infrastructure under
  `tests/conformance/`: a typed `ScenarioConformanceFixture`, reusable
  declaration/registry/behavioural checks, and an independent full-lifecycle
  probe scenario (T9999). The same checks validate both the built-in T1078
  scenario and the probe, separated into declaration, isolated-registry,
  behavioural, and production built-in/CLI conformance. Behavioural conformance
  includes negative tests proving each authoring invariant is enforced
  (duplicate entity/event IDs, unresolved event/finding references,
  nondeterministic simulation or detection, non-dry-run/approval-less/non-
  planned response actions, unsatisfied capability dependencies). An AST-based
  import guard in production conformance proves the reusable sources never
  import a `duke.*.t1078` implementation module.
- Metadata and production checks kept separate: the generic checks validate
  the `Scenario` returned by the metadata loader (no YAML requirement); only
  the T1078 production conformance test asserts agreement with its YAML
  definition.
- The reusable conformance helpers, fixture, and probe callables are checked
  under strict mypy (`mypy src tests/conformance`) via a narrow `pyproject`
  override that exempts only the thin pytest driver modules from untyped-def
  rules.
- Scenario authoring and conformance documentation under `docs/scenarios/`
  (`scenario-authoring.md`, `scenario-conformance.md`) and updated
  scenario-registry, testing, README, roadmap, and changelog entries.


### Changed

- `Scenario.attack_tactic` was replaced by `attack_tactics` so one
  ATT&CK technique can map accurately to multiple tactics.
- CLI lifecycle commands no longer import or call T1078-specific capability
  functions directly; they resolve scenarios and dispatch to capabilities
  through the static built-in `duke.scenarios` registry (T1078 remains in help
  examples and default filenames).
