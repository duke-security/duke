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
- Deterministic, explainable **T1110 investigation** (`duke investigate
  T1110`). It consumes the existing finding (never rerunning detection or
  rescanning the artefact) and builds an `InvestigationResult` strictly from
  `finding.event_ids`: one `SUPPORTS` `Evidence` per referenced failed
  authentication, with a credited later success framed only as supporting
  evidence (consistent with a credential having validated, never proof of
  compromise), a chronological timeline ordered by `occurred_at` then event
  ID that preserves each source event's original target IDs, and involved
  entities resolved from `finding.entity_ids` (source plus sprayed accounts;
  the shared authentication service stays context and is never implicated).
  Account classification relies on resolved entity types, never on
  subtracting the actor or duplicating detection's service logic. Confirmed
  facts are strictly telemetry-derived and distinguish referenced failures,
  resolved implicated targets, and unresolved references; interpretation
  lives only in analyst assessments; unresolved questions cover source
  authorization, failure cause, success legitimacy, follow-on account
  activity, and off-window source activity. Missing referenced events or
  entities are skipped without substitution, and a deterministic
  incompleteness question/assessment is added; an empty or fully unresolved
  `event_ids` set returns an empty result with the incompleteness question,
  never a failure. No confirmed compromise, malicious attribution, credential
  theft, impact, or successful intrusion is ever asserted. Includes unit,
  CLI, registry, missing-reference, portal-context, determinism, and cautious-
  language tests.
- Deterministic, safe dry-run **T1110 response planning** (`duke respond
  T1110`). `plan_t1110_response(artefact, result)` consumes the existing
  investigation result (never rerunning detection or investigation) and
  correlates the finding into a deterministic preliminary `Incident` record
  before proposing actions grouped by category (containment, evidence
  preservation, investigation follow-up, recovery). Every action is
  `dry_run=True`, `requires_approval=True`, and `status=PLANNED`, with a
  deterministic `uuid5` ID and finding-derived timestamp; nothing executes,
  contacts, or modifies a real account, session, credential, MFA, permission,
  network, or security control. Targets are evidence-led: the source is the
  unique actor across the finding-referenced events intersected with the
  investigated entities, and the success-associated account is the uniquely
  resolved, finding-scoped `ACCOUNT` target of a referenced success. Source
  containment is a temporary rate limit/challenge conditioned on ruling out
  shared NAT, proxy, scanner, identity provider, or corporate egress — never
  an unconditional permanent block. Session revocation and credential
  rotation are conditional on a verified success-associated account and human
  approval. A `apply-temporary-step-up-authentication` recovery action is a
  clearly temporary, reversible challenge whose rollback never weakens the
  baseline MFA/security requirements. Rollback is conservative: session and
  credential changes are irreversible (prior credentials never restored),
  preserved evidence is never deleted, review/monitoring actions have no
  rollback, and the source throttle is reversible only without weakening
  existing controls. Ambiguous or unresolved sources or success accounts
  cause the related targeted action to be omitted, and incomplete context is
  recorded in the incident summary; targeted actions are never emitted with a
  `None` target. Wording is cautious throughout (suspected password-spraying
  behaviour, possible credential validation, no confirmed compromise or
  attribution). Includes unit, CLI, registry, model, side-effect,
  cautious-language, target-resolution, rollback, and conformance tests.
- Deterministic, side-effect-free **T1110 validation** (`duke validate
  T1110`). `validate_t1110(artefact)` proves the detection → investigation →
  response-planning pipeline with a fixed, ordered 19-case catalogue
  exercised against immutable, in-memory mutations built in dedicated
  `duke.validation.mutations_t1110` helpers (deterministic `uuid5` namespaces
  for cloned events and created entities, no `uuid4`/wall-clock). Every
  finding-producing case asserts an exact finding count, confidence (80 for
  the canonical corpus, 65 or 60 at the credit/threshold boundaries), and
  severity (HIGH/MEDIUM), runs investigation and response, and verifies every
  response action is dry-run, approval-required, and `PLANNED`; no-finding
  cases stop after detection and prove investigation/response were not
  invoked. The catalogue exercises the detector's hard boundaries: the
  five/four-account threshold, repeated failures (counted once and retained in
  `event_ids`), shared-service exclusion, mixed source actors, single-account
  guessing, an unrelated early failure, attempts split beyond the 30-minute
  window, deterministic earliest-window selection between two equal bursts,
  missing actors, success-credit rules (before the failure, against an
  unrelated account, outside the window, or removal of success), plus a benign
  control, determinism, traceability, and response-safety cases. The source
  artefact is snapshotted and proven structurally unchanged, the input file
  bytes are verified unchanged via the CLI, and per-case exceptions are
  converted into deterministic FAILED results without aborting the suite. An
  exhaustiveness test pins the exact ordered set of 19 case IDs so cases
  cannot silently disappear or reorder. Includes a minimal scoped fix so the
  detector's documented "earliest window start" tie-break matches its code.
  Includes unit, mutation, pipeline, CLI, conformance, determinism,
  immutability, no-I/O, and failure-reporting tests.
- Deterministic **T1110 incident reporting** (`duke report T1110`).
  `report_t1110(artefact, finding, result, plan, suite)` aggregates the
  existing workflow data into a typed `IncidentReport` and renders it with the
  shared, scenario-agnostic renderer as the same 12-section Markdown structure
  used by T1078. The report establishes a deterministic identity
  (`report_id = uuid5(1110e000-…, f"report:{finding.id}")`,
  `generated_at = finding.created_at`; no wall-clock/randomness). Entity roles
  are derived safely and deterministically — source from the unique
  finding-referenced actor, sprayed-account only for finding-scoped
  `EntityType.ACCOUNT` entities, a uniquely-resolved success-associated
  account noted as `sprayed account; later success observed`, contextual
  authentication services never labelled sprayed accounts, and the neutral
  `involved entity` fallback on ambiguity — never from fixed identifiers,
  names, IPs, order, or literals. The generic renderer was minimally
  generalized (report-carried `title`, `technique_label`, `entity_roles`
  with index-aligned coverage validation, and `involved_entities_intro`),
  with **T1078 report bytes preserved byte-for-byte** (verified against a
  pre-refactor golden fixture). Report export is **atomic**: writes a unique
  temporary file, then atomically replaces the destination only on success,
  cleaning up on failure and never leaving a partial file; `--force`
  overwrites. The CLI report flow requires exactly one finding and runs the
  registered validation capability **exactly once** before constructing or
  exporting a report; zero-finding and multi-finding inputs short-circuit to
  0/1 respectively without validation or downstream execution, and no file is
  written on validation failure, wrong finding count, render failure, missing
  `--force`, or malformed input. Narrative is cautious throughout (suspected
  password-spraying behaviour, possible credential validation, no confirmed
  compromise/credential-theft/attribution/intrusion/impact); the finding title
  is shown only as an analytic label, confirmed facts stay distinct from
  assessments, incomplete-context wording is preserved, and rollback rendering
  never deletes evidence, restores old credentials, or weakens MFA. Includes
  model, aggregation, renderer, export (atomic-failure-injection), CLI,
  registry, conformance, determinism, cautious-language, escaping, rollback,
  input-immutability, and T1078 golden-byte tests.
- Deterministic, defensive **T1110 guided learning** (`duke learn T1110`). An
  11-step, metadata-only learning path that teaches Python through Duke's
  T1110.003 Password Spraying workflow, reusing the six existing learning
  models unchanged and a one-line `render_path` generalization
  (`path.technique_id` instead of a literal `T1078`, byte-identical for T1078).
  Content is strictly defensive — it never teaches real spraying, credential
  acquisition, evasion, target discovery, or offensive tools, and it always
  distinguishes Duke's synthetic simulation from a real authentication attempt.
  Every step carries learning objectives, Python concepts, real command
  examples, an explanation, a hands-on exercise with a deterministic expected
  result, ordered hints, a self-check knowledge check, and an explicit safety
  note. Taught numbers are verified against the live public pipeline by tests
  to prevent documentation drift; snippets use only documented public imports
  (never private or `duke.*.t1110` implementation modules); Rich-sensitive
  Python renders literally; and the package has no subprocess, network,
  filesystem-write, grading, or persistence code. With learning registered,
  T1110 now provides all seven registered capabilities and joins the
  full-lifecycle conformance fixture set (T1078, T1110, and the independent
  probe), while production `builtin_registry()` still contains exactly T1078
  and T1110. Includes model, catalogue, render, CLI, public-import, fidelity,
  safety, side-effect, determinism, registry, conformance, and T1078
  byte-output tests.
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
- **Apache License 2.0** licensing and package metadata hardening: a root
  `LICENSE` file, `license = "Apache-2.0"` + `license-files = ["LICENSE"]`
  package metadata, an `authors` entry, `keywords`, and accurate `classifiers`
  (Education / Information Technology / Security); README's License
  section now states Apache-2.0 and links the license text.

### Documentation

- **Phase 1 portfolio / release-preparation documentation**: architecture
  component diagram (`docs/architecture/components.md`) and lifecycle /
  data-flow diagram (`docs/architecture/lifecycle.md`), a concise README
  showcase ("Try Duke"), a reproducible end-to-end T1110 demonstration
  (`docs/development/reproducible-demo.md`), and a `0.2.0` release-readiness
  checklist (`docs/release/0.2.0-release-readiness.md`). No runtime code or
  tests changed; the source version remains `0.1.0` and no release action
  was taken.

### Changed

- `Scenario.attack_tactic` was replaced by `attack_tactics` so one
  ATT&CK technique can map accurately to multiple tactics.
- CLI lifecycle commands no longer import or call T1078-specific capability
  functions directly; they resolve scenarios and dispatch to capabilities
  through the static built-in `duke.scenarios` registry (T1078 remains in help
  examples and default filenames).
- Release-metadata hardening: the `build` frontend is now declared in the
  `dev` extra, `[build-system] requires` is set to `setuptools>=77` (for the
  PEP 639 license metadata), `.claude/` is explicitly gitignored, and the
  scenario-version policy is documented under `docs/scenarios/` (scenario
  metadata/content versions are independent of the Duke package version;
  this slice changes neither). Source version remains `0.1.0`; no release
  action was taken.
