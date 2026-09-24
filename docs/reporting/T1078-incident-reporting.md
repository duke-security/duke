# T1078 — Deterministic Incident Reporting

## Overview

`duke report T1078` renders a deterministic, advisory incident report
from the data already produced by earlier Duke stages. It consumes the
existing `TelemetryArtefact`, `Finding`, `InvestigationResult`,
`ResponsePlan` (from `duke respond`), and `ValidationSuiteResult` (from
`duke validate`) — it never regenerates telemetry, never modifies the
source artefact, never executes a response action, and never asserts a
confirmed compromise, impact, or exfiltration.

The report is advisory and analytic: it records observables, evidence,
analysis, and dry-run-only recommendations.

## Workflow

```bash
duke simulate T1078 --output data/events/t1078-session-001.json
duke detect T1078 --input data/events/t1078-session-001.json
duke investigate T1078 --input data/events/t1078-session-001.json
duke respond T1078 --input data/events/t1078-session-001.json
duke validate T1078 --input data/events/t1078-session-001.json
duke report T1078 \
  --input data/events/t1078-session-001.json \
  --output reports/t1078-incident-report.md
```

`duke report T1078` runs the pipeline's stages once each and then builds
an `IncidentReport` (`report_t1078`), renders it deterministically to
Markdown (`render_incident_report`), and writes it safely
(`export_report`).

## Data flow

```
TelemetryArtefact ─ detect_t1078 ─> Finding(s)
TelemetryArtefact + Finding ─ investigate_t1078 ─> InvestigationResult
TelemetryArtefact + InvestigationResult ─ plan_t1078_response ─> ResponsePlan
TelemetryArtefact ─ validate_t1078 (exactly once) ─> ValidationSuiteResult
   └─ (report_t1078(artefact, finding, result, plan, suite)) ─> IncidentReport
        └─ render_incident_report ─> str        └─ export_report ─> file
```

Reporting is a pure read/aggregate/render stage over these existing,
typed inputs; no new telemetry is generated and no output is produced for
a benign artefact.

## Report identity and timestamp

- **Report ID**: `uuid5(REPORT_NAMESPACE, "report:" + finding.id)` where
  `REPORT_NAMESPACE` is the deterministic `1078d000-…` namespace. The same
  finding always yields the same report ID.
- **Generated timestamp**: `generated_at = finding.created_at`, which is
  itself derived from the anchor event (`new_login.occurred_at`) during
  detection. It is **not** the wall-clock export time — reporting contains
  no `datetime.now()`, so the report timestamp is fully reproducible from
  the artefact.

## Report structure (deterministic Markdown)

| # | Section | Content |
|---|---|---|
| 1 | Report identification | report ID, generated timestamp, technique |
| 2 | Executive summary | cautious narrative `executive_summary` |
| 3 | Scope and methodology | `scope_summary` + ordered `methodology` steps |
| 4 | Finding | title (labelled *analytic label; not confirmation*), detection rule, technique, severity, status, confidence, description, detection rationale |
| 5 | Involved entities | account, unfamiliar device, resources, external destination |
| 6 | Chronological timeline | timestamp, exact `SecurityEvent` ID, summary |
| 7 | Evidence register | `Evidence` ID, source-event ID, relationship, description |
| 8 | Analysis | confirmed facts / analyst assessments / unresolved questions |
| 9 | Recommended response | grouped by category (containment, evidence preservation, investigation follow-up, recovery) with DRY RUN ONLY / APPROVAL REQUIRED / NOT EXECUTED labels, verification, and rollback guidance |
| 10 | Validation summary | all 16 cases and overall pass/fail |
| 11 | Limitations | cautious bounds |
| 12 | Conclusion | cautious closing that does not assert compromise, impact, or exfiltration |

The renderer escapes every dynamic value placed in a table (pipes become
`\|`, line breaks become spaces), so entity names, descriptions, evidence,
and timeline summaries cannot corrupt the table structure. Identical inputs
produce byte-identical Markdown ending in exactly one newline.

### Rollback rendering

- When an action `supports_rollback`, its `rollback_guidance` is rendered.
- When `supports_rollback=False`, the renderer writes
  `Not applicable — no rollback guidance`. Review-only actions (e.g.
  confirming account ownership or assessing exfiltration risk) are *not*
  described as "irreversible", because they make no system change.

## Cautious-language safeguards

- A fixed advisory banner on every report reads that it does not assert
  account compromise, data exfiltration, or impact, and that no action was
  executed.
- The finding title (whose text includes "Compromised identity") is
  rendered only under the label *analytic label; not confirmation* and is
  never repeated as an established fact in the executive summary or
  conclusion.
- Every response recommendation carries the global DRY RUN ONLY —
  APPROVAL REQUIRED — NOT EXECUTED label.
- Tests assert the safe phrases are present and that unqualified
  overclaims are absent.

## Safe export

`export_report(markdown, path, *, overwrite=False)` refuses to overwrite
an existing file unless `overwrite=True` (CLI `--force`). It creates
parent directories and writes the report with exactly one trailing
newline.

## CLI behaviour and exit codes

```
$ duke report T1078 --input data/events/t1078-session-001.json --output reports/…md
Report complete
Report ID: 159c22b3-…
Validation: 16/16 cases passed
Saved: reports/…md
```

| Case | Output | Exit |
|---|---|---|
| valid artefact, all checks | report written | 0 |
| valid benign artefact (no finding) | "No findings to report", no output file | 0 |
| invalid artefact (missing/malformed/bad schema/entity/event) | error message | 1 |
| failed validation (`all_passed` is false) | "Validation failed", no output file | 1 |
| more than one finding | "Expected exactly one finding", no output file | 1 |
| output file already exists (no `--force`) | "Output already exists…" | 1 |
| export failure (`OSError`) | error message | 1 |
| unsupported technique | "Unsupported technique" | 2 |

Validation runs **exactly once**, before any report is constructed, and
must pass. Reporting requires **exactly one** T1078 finding; it never
loops over multiple findings into one output path and never silently
selects the first.

## Limitations

- The report is advisory and derived from synthetic lab data; it is not a
  confirmed incident or a final incident report.
- It does not assert account compromise, data exfiltration, or impact.
- Response actions are dry-run recommendations only; none are executed.
- The report timestamp is the deterministic detection timestamp, not the
  wall-clock export time.
- No PDF/HTML rendering, real response execution, adapters, or additional
  scenarios are implemented.

## References

- MITRE ATT&CK — T1078 Valid Accounts (https://attack.mitre.org/techniques/T1078/)
- [T1078 lab documentation](../labs/T1078/overview.md)
- [T1078 investigation documentation](../investigations/T1078-compromised-identity.md)
- [T1078 response documentation](../responses/T1078-safe-response.md)
- [T1078 detection validation documentation](../validation/T1078-detection-validation.md)

## Last reviewed

2026-09-23
