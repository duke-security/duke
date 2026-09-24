# T1078 — Deterministic Detection Validation

## Overview

This document describes how Duke validates its T1078 detection,
investigation, and response-planning pipeline. `duke validate T1078`
(`validate_t1078`) proves that the pipeline behaves correctly by consuming
an existing telemetry artefact, preserving it untouched, and rerunning the
full workflow — detection → investigation → response planning — against
controlled, **in-memory** mutations.

Validation is deterministic and side-effect-free: it never modifies the
source artefact, never writes files, never touches a network, and never
executes a real response action.

## Workflow

```bash
duke simulate T1078 --output data/events/t1078-session-001.json
duke validate T1078 --input data/events/t1078-session-001.json
```

`duke validate T1078` loads the artefact with `load_telemetry_artefact`
(the existing loader — no JSON/validation logic is duplicated), then calls
`validate_t1078(artefact)`, which returns a `ValidationSuiteResult`
containing one `ValidationCase` per check: case name, expected outcome,
actual outcome, pass/fail status, and explanation.

## The canonical T1078 corpus

The shipped corpus yields a single finding with **confidence 90**: the
new-context login (25 points) plus repository enumeration (10), restricted
file access (15), privileged-access request (15), archive creation (10),
and network egress (15) — at or above the detection threshold of 60.

## Validation cases

| Case | Mutation (in-memory only) | Expected |
|---|---|---|
| `suspicious-corpus-unmodified` | none | 1 finding, confidence 90, 9 safe actions |
| `missing-known-good-baseline` | drop the known-good baseline login | no findings |
| `missing-new-context-authentication` | drop the new-context login | no findings |
| `insufficient-confidence` | drop restricted/privileged/egress (→ 45) | no findings |
| `correlation-window-expiry` | shift follow-ons ≥ 30 min past the login | no findings |
| `wrong-actor` | re-attribute follow-ons to a baseline-less actor | no findings |
| `duplicate-behaviours-not-inflating` | insert a distinctly-IDed clone of one follow-on | confidence stays 90 |
| `remove-repository-enumeration` | drop the enumeration event | confidence 80 |
| `remove-restricted-file-access` | drop the restricted-read event | confidence 75 |
| `remove-privileged-access-request` | drop the privileged-request event | confidence 75 |
| `remove-archive-creation` | drop the archive event | confidence 80 |
| `remove-network-egress` | drop the egress event | confidence 75 |
| `benign-no-finding` | keep only baseline + routine access | no findings, no actions |
| `deterministic-repeatability` | none; run twice | identical result |
| `evidence-and-timeline-traceability` | none | evidence IDs == finding event IDs; chronological timeline |
| `response-actions-dry-run-safe` | none | all actions dry-run, approval-required, PLANNED |

The five `remove-*` cases are separate, explicit cases — each reports its
own expected and actual confidence rather than hiding sub-checks inside one
result.

## Source-artifact immutability

- The supplied `TelemetryArtefact` is **never modified**. Every mutation
  builds a new artefact from copied or new model instances (immutable
  tuples and `SecurityEvent.model_copy(update=...)`), so no original event
  or entity object is changed.
- Cloned events receive a distinct deterministic ID (via a fixed namespace
  and `uuid5`), so no two events ever share an identifier.
- `validate_t1078` snapshots the source artefact (via `model_dump`)
  **before** validation and compares it **afterward**, raising if it ever
  changed.
- The validation module contains **no file-writing or network code**; it
  only reads the input artefact once through the CLI. A test scans the
  package source to enforce this.

## `ValidationSuiteResult.all_passed`

`all_passed` is a read-only property derived from the contained cases: it
is always `True` exactly when every case has PASS status. Because callers
cannot set it, a suite can never be constructed with an inconsistent flag.

## CLI behaviour and exit codes

```
$ duke validate T1078 --input data/events/t1078-session-001.json
PASS suspicious-corpus-unmodified — 1 finding, confidence 90, 9 safe actions
PASS missing-known-good-baseline — no findings
...
Validation complete: 16/16 cases passed
```

- **exit 0** — artefact valid and all validation cases pass (including the
  internal benign/no-finding mutation, which is itself a passing case).
- **exit 1** — invalid artefact (missing file, directory, malformed JSON,
  unsupported schema version, invalid entity/event record), **or** a
  validation suite that failed (e.g. an externally supplied benign artefact
  that cannot satisfy the canonical T1078 corpus expectations).
- **exit 2** — unsupported technique.

## Limitations

- Validation exercises Duke's own detection rule against its own corpus and
  mutations; it asserts internal consistency and expected behaviour, not
  real-world precision/recall.
- It does not implement reporting, real response execution, adapters,
  automatic remediation, or additional techniques.

## References

- MITRE ATT&CK — T1078 Valid Accounts (https://attack.mitre.org/techniques/T1078/)
- [T1078 lab documentation](../labs/T1078/overview.md)
- [T1078 detection documentation](../labs/T1078/overview.md#detection-methodology)
- [T1078 investigation documentation](../investigations/T1078-compromised-identity.md)
- [T1078 response documentation](../responses/T1078-safe-response.md)

## Last reviewed

2026-09-23
