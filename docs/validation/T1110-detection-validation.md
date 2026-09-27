# T1110 — Deterministic Detection Validation: Password Spraying

## Overview

This document describes how Duke validates the T1110.003 Password Spraying
detection → investigation → response-planning pipeline. `duke validate T1110`
runs `validate_t1110`, which applies an ordered catalogue of controlled,
in-memory mutations to a telemetry artefact and records, for each case, its
expected outcome, the actual outcome, and whether they agree.

Validation operates entirely in memory: the supplied artefact is never
modified, no file or network is touched, and no real response action is
executed. Every result is deterministic, and the 19-case catalogue is fixed
and order-stable so cases cannot silently disappear or reorder.

## Workflow

```bash
duke simulate T1110 --output data/events/t1110-session-001.json
duke validate T1110 --input data/events/t1110-session-001.json
```

The canonical T1110 corpus yields 19/19 passing cases. Exit codes match the
other stages:

- `0` — every case passed (`Validation complete: 19/19 cases passed`);
- `1` — one or more cases failed, or the input artefact is invalid/missing;
- `2` — unsupported scenario or capability.

## Determinism and immutability

- Mutations use fixed `uuid5` namespaces (`1110d000-*` for cloned events,
  `1110d001-*` for newly created entities), never `uuid4` or wall-clock time.
- Each mutation returns a brand-new `TelemetryArtefact`; the supplied artefact
  is snapshotted (deep `model_dump`) before and after and validation raises if
  it was ever mutated.
- All new actor/account/service/target IDs are backed by real, resolvable
  entities so every positive-pipeline reference resolves.
- The input JSON file bytes are verified unchanged by the CLI (`duke validate
  T1110` does not rewrite it).

## The ordered 19-case catalogue

Each case reports a stable name, the explicit mutation, an expected outcome,
the actual outcome, and a concise explanation of the invariant it proves.
Finding-producing cases run detection → investigation → response and assert
exact confidence, severity, and response-action counts; no-finding cases stop
after detection and assert that investigation and response were not invoked.

| # | Case ID | Expected outcome | Invariant |
|---|---|---|---|
| 1 | `suspicious-corpus-unmodified` | 1 finding, 80 (HIGH), 1 investigation result, 9 safe actions | Canonical full pipeline |
| 2 | `bare-spray-no-success` | 1 finding, 65 (MEDIUM), 6 safe actions | Spray fires with no success |
| 3 | `success-before-failure-no-credit` | 1 finding, 65 (MEDIUM) | Success must post-date its account's failure |
| 4 | `success-other-account-no-credit` | 1 finding, 65 (MEDIUM) | Success must hit a previously-failed account |
| 5 | `success-outside-window-no-credit` | 1 finding, 65 (MEDIUM) | Success must fall inside the window |
| 6 | `five-distinct-accounts-threshold` | 1 finding, 60 (MEDIUM) | Threshold fires at the floor |
| 7 | `four-distinct-accounts-below-threshold` | no findings | Sub-threshold does not fire |
| 8 | `repeated-failures-do-not-inflate` | 1 finding, 65 (MEDIUM), repeat retained | Repeats counted once |
| 9 | `shared-service-not-counted` | 1 finding, 80 (HIGH); added service never implicated | Shared service is not an account |
| 10 | `mixed-source-actors-no-aggregation` | no findings | Mixed sources don't aggregate |
| 11 | `single-account-guessing-no-finding` | no findings | Single-account guessing isn't a spray |
| 12 | `unrelated-early-failure-does-not-hide-later-spray` | 1 finding, 80 (HIGH); early account not implicated | Sliding window ignores unrelated early failures |
| 13 | `split-beyond-window-no-finding` | no findings | No window holds 5+ distinct accounts |
| 14 | `deterministic-multi-window-selection` | 1 finding, 60 (MEDIUM); earliest window selected | Earliest-window tie-break |
| 15 | `missing-actor-no-finding` | no findings | No actor → no correlation |
| 16 | `benign-no-finding` | no findings, no response actions | Benign control |
| 17 | `deterministic-repeatability` | stable output over two runs | Full determinism |
| 18 | `evidence-and-timeline-traceability` | evidence/timeline match the finding | Event references resolve & are chronological |
| 19 | `response-actions-dry-run-safe` | all 9 actions dry-run/approval/PLANNED | Response-plan safety |

Negative cases are successful validations when the observed result matches
the expected absence of a finding; any unexpected finding, wrong
confidence/severity, unsafe response output, unresolved reference, or
non-deterministic result marks the case FAIL and, because the runner never
stops at the first failure, all case results are reported in order.

## Safety boundaries

Validation reruns detection, investigation, and response planning only. It
performs no real authentication, no account/session/credential/MFA changes,
no blocking, and no response execution, and it never touches a file system or
network from inside `duke.validation`.

## Limitations

- Validation is corpus-parametric: it is designed to validate the canonical
  T1110 pipeline. A genuinely benign artefact produces a failing suite, as
  expected.
- Case 14 constructs a bespoke two-burst scenario to prove the earliest-window
  tie-break; deeper equal-timestamp event-ID tie behaviour is covered by the
  detection unit tests.

## References

- MITRE ATT&CK — T1110 Brute Force (https://attack.mitre.org/techniques/T1110/),
  T1110.003 Password Spraying (https://attack.mitre.org/techniques/T1110/003/)
- [T1110 lab documentation](../labs/T1110/overview.md)
- [T1110 response documentation](../responses/T1110-safe-response.md)
- [Architecture Decision Records](../decisions/)

## Last reviewed

2026-09-27
