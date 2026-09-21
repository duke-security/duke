# Duke Agent Instructions

## Project

Duke is a vendor-agnostic, interactive cybersecurity education and
security-engineering platform written primarily in Python.

Duke teaches Python through realistic security workflows:

Learn
→ Simulate
→ Observe
→ Detect
→ Investigate
→ Respond
→ Validate
→ Document
→ Improve
→ Retest

This lifecycle is continuous. Improvements must be retested to confirm
that detections, controls, and response processes work as intended.

## Current Objective

The first milestone is one complete vertical security scenario based on
MITRE ATT&CK T1078 — Valid Accounts.

The milestone must demonstrate:

1. Safe scenario simulation
2. Normalized telemetry generation
3. Behaviour-based detection
4. Evidence-led investigation
5. Safe dry-run response
6. Detection validation
7. Professional incident reporting
8. Tests and documentation

Do not implement the entire roadmap or all ATT&CK tactics at once.

## Core Principles

1. Keep Duke's core vendor-agnostic.
2. Build the CLI before an API, TUI, or web interface.
3. Use MITRE ATT&CK as a behavioural taxonomy, not as a collection of
   attack scripts.
4. Use modern and realistic security scenarios.
5. Simulate potentially harmful adversary behaviour safely.
6. Use synthetic data and isolated environments.
7. Prefer reproducing observable telemetry over implementing offensive
   capability.
8. Use typed, readable Python.
9. Keep all important components independently testable.
10. Develop in small vertical slices.
11. Preserve clear boundaries between learning, simulation, telemetry,
    detection, investigation, response, validation, and reporting.
12. Use normalized internal security models.
13. Introduce provider-specific functionality through adapters.
14. Avoid unnecessary abstraction.
15. Run all required quality checks before declaring work complete.

## Safety Requirements

Never implement:

- destructive malware or ransomware
- credential theft
- uncontrolled persistence
- security-product disabling
- real data exfiltration
- unauthorized access
- uncontrolled exploitation
- code intended to evade real defensive systems

For sensitive ATT&CK techniques, reproduce only their observable effects
using synthetic events, harmless files, temporary directories, and
isolated lab environments.

Every simulation must:

- explain what is being simulated
- state what is intentionally not implemented
- use synthetic or disposable data
- avoid modifying real security settings
- support safe cleanup where applicable
- be suitable for an authorized training environment

## Architecture

Duke's planned components are:

- `core`: shared domain models, interfaces, configuration, and registry
- `cli`: Typer-based command-line interface
- `learning`: Python lessons, exercises, and challenges
- `simulation`: safe behaviour and scenario simulation
- `telemetry`: normalized security-event generation and ingestion
- `detection`: detection rules, correlation, and quality testing
- `investigation`: evidence, timelines, hypotheses, and graphs
- `response`: safe response plans, approvals, dry runs, and rollback
- `reporting`: incident reports, summaries, and lessons learned
- `labs`: guided end-to-end learning experiences
- `adapters`: optional vendor or platform integrations

The core must not depend directly on AWS, Azure, GCP, a particular SIEM,
EDR, or other security vendor.

Provider-specific data must be translated into Duke's normalized models
through adapters.

## Domain Model Direction

The initial domain model will eventually include:

- SecurityEvent
- Entity
- Evidence
- Finding
- Incident
- ResponseAction
- Scenario

Do not add models without clear purpose, tests, and documentation.

## Scenario Design

Scenarios should be metadata-driven where practical.

A scenario may eventually contain:

- `scenario.yaml`
- safe simulation logic
- detection logic
- investigation guidance
- response guidance
- validation tests
- scenario documentation

Scenario metadata should support:

- scenario identifier
- name and description
- ATT&CK technique and tactic
- learning objectives
- Python concepts
- telemetry requirements
- safety classification
- references
- version
- last-reviewed date

Do not hardcode the complete scenario catalogue into the CLI.

## Documentation Policy

Documentation is mandatory.

If we build it, we document it.
If we change it, we update its documentation in the same change.

Every implementation task must consider updates to:

- `README.md`
- `CHANGELOG.md`
- `ROADMAP.md`
- architecture documentation
- development documentation
- lab documentation
- detection documentation
- investigation documentation
- response documentation
- reporting documentation
- Architecture Decision Records

A feature is not complete when its documentation is missing or outdated.

Create an Architecture Decision Record under `docs/decisions/` when a
change introduces a significant architectural decision.

## Lab Documentation Requirements

Every completed security lab should document:

- learning objectives
- required Python knowledge
- security scenario
- threat relevance
- ATT&CK mapping
- safety boundaries
- generated telemetry
- detection methodology
- expected false positives
- investigation workflow
- supporting evidence
- response methodology
- validation approach
- hardening recommendations
- limitations
- references
- last-reviewed date

## Incident Documentation Requirements

Investigation notes should be recorded throughout an incident.

The final incident report should answer:

- Who was involved?
- What happened?
- When did it happen?
- Where did it happen?
- Why did it succeed?
- How did it happen?
- What evidence supports the conclusion?
- What was the impact?
- How was it detected?
- What response actions were taken?
- What telemetry or control gaps existed?
- What should be improved?
- Was the improvement successfully retested?

Reports must distinguish confirmed facts, analyst assessments, and
unresolved questions.

## Testing and Quality

New behaviour requires tests.

Before completing a change, run:

```bash
ruff check .
mypy src
pytest

