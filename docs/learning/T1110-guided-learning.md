# T1110 — Guided Learning: Password Spraying

## Overview

`duke learn T1110` walks a beginner through Duke's defensive T1110.003
Password Spraying workflow while teaching Python. It is an 11-step,
deterministic, metadata-only path that spans simulation, detection,
investigation, response, validation, and reporting — always on synthetic data.

The learning package is **content only**: it never executes a command, never
writes or modifies a learner's files, never makes a network or subprocess
call, never grades work, and never persists progress. Command examples are
literal, inert printed text referencing real, implemented Duke CLI commands;
exercises may ask you to inspect Duke objects or write local Python snippets,
but Duke itself never runs your snippets.

## Safety boundary

This path studies the **defensive telemetry** of many failed authentications
against distinct accounts from one source inside a bounded window. It never
teaches real password spraying, password-list construction, credential
acquisition, evasion, target discovery, or any offensive tool. Duke's
simulation reproduces only the observable effects on synthetic data in an
isolated lab — it is never a real authentication attempt. Throughout, a Duke
finding is an *analytic signal*, never proof of compromise.

## The 11-step catalogue

| # | ID | Title | Lifecycle stage |
|---|---|---|---|
| 1 | `orientation` | Orientation and safety | Orientation |
| 2 | `collections` | Python collections | Telemetry |
| 3 | `typed-models` | Typed models and validation | Telemetry / models |
| 4 | `datetime` | The sliding 30-minute window | Detection |
| 5 | `functions-modules` | Functions and modules | Simulation / detection |
| 6 | `detection` | Detection reasoning | Detection |
| 7 | `investigation` | Evidence-led investigation | Investigation |
| 8 | `response` | Safe response planning | Response |
| 9 | `validation` | Detection validation | Validation |
| 10 | `reporting` | Reporting | Reporting |
| 11 | `final-challenge` | Final challenge: the full defensive workflow | All six |

Each step includes learning objectives, Python concepts, real command
examples, an explanation, a hands-on exercise with a deterministic expected
result, ordered hints, a knowledge check with a **reference answer
(self-check)** (never auto-graded), and an explicit safety note.

## Use

```bash
duke learn T1110
duke learn T1110 --step detection
duke learn T1110 --step investigation
duke learn T1110 --step response
duke learn T1110 --step validation
duke learn T1110 --step reporting
duke learn T1110 --step final-challenge
```

Exit codes: `0` — the overview or a requested step rendered; `2` — unknown
step or unknown scenario. Rendering writes no files and makes no
network/subprocess calls.

## Taught values

Content teaches the canonical T1110 corpus numbers exactly: 10 entities and 8
events, detected as 1 finding at confidence 80 (severity high) with 7
supporting events, 7 investigation evidence items, a 9-action dry-run response
plan, a 19-case validation suite (19/19 passing), and a 12-section report.
These numbers are verified against the live public pipeline by tests to
prevent documentation drift.

## Conformance and lifecycle

With learning registered, T1110 now provides all seven registered lifecycle
capabilities (simulation, detection, investigation, response, validation,
reporting, learning) and joins the full-lifecycle conformance fixture set.
Broader future work — additional scenarios, adapters, a GUI/API, progress
tracking, auto-grading, and real response execution — remains planned; T1110's
completion does not mean the entire Duke roadmap is finished.

## References

- MITRE ATT&CK — T1110 Brute Force (https://attack.mitre.org/techniques/T1110/),
  T1110.003 Password Spraying (https://attack.mitre.org/techniques/T1110/003/)
- [T1110 lab documentation](../labs/T1110/overview.md)
- [T1110 reporting documentation](../reporting/T1110-incident-reporting.md)
- [Architecture Decision Records](../decisions/)

## Last reviewed

2026-09-28
