# T1110 — Deterministic Incident Reporting: Password Spraying

## Overview

This document describes how Duke renders a deterministic, advisory incident
report for the T1110.003 Password Spraying scenario. `duke report T1110`
aggregates the existing workflow data — the telemetry artefact, the `Finding`,
the evidence-led `InvestigationResult`, the dry-run `ResponsePlan`, and the
`ValidationSuiteResult` — into a typed `IncidentReport` and renders it as
Markdown using the shared, scenario-agnostic renderer and atomic-safe export.

Reporting aggregates; it never regenerates telemetry and never reruns
detection, investigation, response, or validation. It executes no response
action and never asserts a confirmed compromise, credential theft,
attribution, successful intrusion, or impact.

## Workflow

```bash
duke simulate T1110 --output data/events/t1110-session-001.json
duke report T1110 \
  --input data/events/t1110-session-001.json \
  --output reports/t1110-incident-report.md
```

### Report-candidate fail-safe flow and exit codes

The CLI report flow operates on exactly one report-candidate finding:

- **zero findings** → exit `0`, "No findings to report", no output file, and
  validation / investigation / response / report are **not** invoked;
- **exactly one finding** → the registered validation capability runs
  **exactly once**; a failing suite stops before any report is built (exit `1`,
  no file);
- **multiple findings** → exit `1`, no output file, and validation / downstream
  are **not** invoked;
- invalid/missing artefact → `1`; output exists without `--force` → `1`;
  unknown scenario or missing capability → `2`.

This "validation exactly once" guarantee applies to the single-finding
report-candidate path — not to benign input, which short-circuits before
validation.

## Report identity

- `_REPORT_NAMESPACE_T1110 = 1110e000-…`;
- `report_id = uuid5(namespace, f"report:{finding.id}")`;
- `generated_at = finding.created_at` (the deterministic detection timestamp,
  never wall-clock time).

No randomness or unstable collection ordering is used, so identical inputs
always produce byte-identical Markdown ending in exactly one newline.

## Entity roles

Roles are derived deterministically and safely, never from fixed UUIDs,
names, IPs, list position, or corpus literals:

- **source** — the unique finding-referenced event actor that is also an
  involved entity;
- **sprayed account** — a finding-scoped `EntityType.ACCOUNT` involved entity;
- **sprayed account; later success observed** — the uniquely-resolved
  success-associated account (this extends, never erases, the safe
  sprayed-account classification);
- **involved entity** — the neutral fallback for anything not confidently
  classifiable (never guessed).

A shared authentication service is never labelled a sprayed account; it is not
an involved entity and stays out of the report's entity list.

## The 12-section structure

The report uses the same 12 sections and order as T1078, changing only
scenario-provided content:

1. Report identification
2. Executive summary
3. Scope and methodology
4. Finding (title shown only as "analytic label; not confirmation")
5. Involved entities (roles/type/identifier/display name)
6. Chronological timeline
7. Evidence register
8. Analysis (confirmed facts / analyst assessments / unresolved questions)
9. Recommended response (dry-run plan, grouped by category)
10. Validation results (all 19 cases in deterministic catalogue order)
11. Limitations and unresolved questions
12. Conclusion

## Narrative

- A suspicious password-spraying pattern was detected: one source, several
  distinct accounts, inside a bounded window (confidence N/100).
- A referenced later success is supporting behaviour consistent with possible
  credential validation — not proof of compromise.
- Malicious intent, credential theft, attribution, successful intrusion, and
  impact are not confirmed.
- Response actions were dry-run proposals only and were not executed.

Confirmed telemetry facts are kept distinct from analyst assessments, and any
incomplete-context wording from investigation/response is preserved.

## Response and rollback rendering

Each proposed action renders its risk, dry-run status, approval requirement,
`PLANNED`(not-executed) status, verification guidance, and:
- `supports_rollback=True` → the supplied rollback guidance;
- otherwise → `Not applicable — no rollback guidance`.

Review-only actions are never labelled irreversible, and no rollback ever
recommends deleting preserved evidence, restoring old credentials, or
weakening MFA.

## Atomic export

Export writes the complete rendered Markdown to a unique temporary file in the
destination directory, flushes and closes it successfully, and only then
atomically replaces the destination (`os.replace`). A pre-existing destination
is left unchanged if the write or replacement fails, no new destination is left
behind on a failed first-time export, and a failed export leaves no orphan
temporary file. `--force` is required to overwrite an existing output.

## References

- MITRE ATT&CK — T1110 Brute Force (https://attack.mitre.org/techniques/T1110/),
  T1110.003 Password Spraying (https://attack.mitre.org/techniques/T1110/003/)
- [T1110 lab documentation](../labs/T1110/overview.md)
- [T1110 response documentation](../responses/T1110-safe-response.md)
- [T1110 validation documentation](../validation/T1110-detection-validation.md)
- [Architecture Decision Records](../decisions/)

## Last reviewed

2026-09-27
