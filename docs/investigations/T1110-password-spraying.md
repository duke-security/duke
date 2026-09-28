# T1110 — Evidence-Led Investigation: Password Spraying

## Overview

This document describes how to investigate the T1110.003 Password Spraying
scenario evidence-led style. It walks through the workflow implemented by
`duke investigate T1110` (`investigate_t1110`) and records the supporting
evidence, the analytic reasoning, and the questions that remain open.

Investigation is deliberately separate from detection. `duke investigate`
loads a normalized telemetry artefact, runs `detect_t1110` to obtain a
`Finding`, and passes that existing `Finding` into the investigation logic.
Investigation never runs detection itself and never rescans the artefact to
search for a new pattern, so the two components stay independently testable
and the finding's `event_ids` remain the sole event-selection boundary.

## Workflow

```bash
duke simulate T1110 --output data/events/t1110-session-001.json
duke detect T1110 --input data/events/t1110-session-001.json
duke investigate T1110 --input data/events/t1110-session-001.json
```

`duke investigate T1110` builds an `InvestigationResult` containing:

1. the original `Finding`;
2. the **involved entities** resolved from `Finding.entity_ids`;
3. one **`Evidence`** per event referenced by `Finding.event_ids`;
4. a chronological **`TimelineEntry`** per referenced event (ordered by
   `occurred_at`, then event ID);
5. distinct **confirmed facts**, **analyst assessments**, and
   **unresolved questions**.

## Supporting evidence

Only the events referenced by the finding are considered, so every piece of
evidence traces back to a concrete event (`source_event_id`). In the T1110
spray corpus every referenced event is an authentication attempt that the
detector placed in the finding:

- **Failed authentications** contributing to the selected spray window are
  recorded as `SUPPORTS`.
- A **credited later successful authentication** is recorded as `SUPPORTS`,
  and its description explicitly frames it as consistent with a credential
  having validated — **supporting evidence only, never proof of compromise**.
- **Shared authentication-service context** (e.g. the `web-portal` a spray
  is made *through*) is treated as context, not as an implicated account.
  Evidence descriptions name only finding-scoped account targets, and the
  shared service is never returned as an involved entity.

Deterministic evidence identifiers are derived from each referenced event
(a fixed T1110 UUID namespace via `uuid5`), so the same artefact and finding
always produce the same evidence.

## Timeline

The timeline lists the referenced events in ascending chronological order,
breaking ties by event ID. Each timeline entry preserves the original
actor/target IDs of its source event — including a shared-service target — so
the timeline represents the source event faithfully even though that service
is not implicated. For the shipped T1110 corpus, the timeline is:

| Order | Observation |
|---:|---|
| 1 | Failed authentication against `svc.integration` |
| 2 | Failed authentication against `svc.reports` |
| 3 | Failed authentication against `svc.analytics` |
| 4 | Failed authentication against `svc.etl` |
| 5 | Failed authentication against `d.garcia` |
| 6 | Failed authentication against `a.okafor` |
| 7 | Successful authentication to `svc.reports` (supporting evidence) |

## Confirmed facts

Facts are telemetry-derived statements, not interpretation. For the shipped
corpus, the investigation confirms:

- the finding references six failed authentications;
- the implicated target entities of the finding are resolved, and six of
  them are accounts;
- a later successful authentication to one previously-failed account is
  referenced;
- the source host carries telemetry attributes indicating it is
  `zone=internet` and `managed=false`.

If any event or entity referenced by the finding cannot be resolved, the
facts also state how many references are unresolved, and no evidence is
fabricated for the missing objects.

## Analyst assessments

Assessments are the analyst's interpretation of the facts:

- The many-failed-authentications-against-distinct-accounts-from-one-source
  pattern is consistent with password spraying (MITRE ATT&CK T1110.003).
- Failures may reflect hostile activity, but could also be consistent with
  user error, automation, or an authorized but misconfigured service; intent
  is not established by investigation alone.
- If a later success is referenced, it is consistent with a credential
  having validated but does not confirm compromise.

## Unresolved questions

Questions remain open that a full incident response would need to answer:

- Was the source authorized infrastructure?
- Did the failures result from user error, automation, or hostile activity?
- Was the successful authentication (if one was observed) legitimate?
- Did any affected account show subsequent suspicious activity after the
  failures?
- Did the source appear elsewhere or continue activity outside the
  30-minute detection window?
- If any referenced event or entity was unresolved, could it be observed
  through another telemetry source?

## How the investigation was detected

The finding that drives this investigation is produced by `detect_t1110`
(`password-spraying-window`), which infers a spray pattern from a sliding
30-minute window requiring at least five distinct accounts failed from one
source. See the [T1110 lab documentation](../labs/T1110/overview.md).

## Safety boundaries

Investigation operates only on synthetic, deterministic telemetry produced
by `duke simulate`. It performs no access to real systems, no credential
handling, and no remediation. All data is from the exported JSON artefact.

## Limitations

- The investigation reports analysis, not a confirmed compromise; no
  malicious attribution, credential theft, impact, or successful intrusion
  is asserted.
- Only the events the finding references are surfaced; related but
  unreferenced telemetry (including activity outside the 30-minute window)
  is intentionally excluded and surfaces only as unresolved questions.
- Unresolved questions require additional evidence that this slice does not
  attempt to collect.

## Next: response, validation, reporting

`duke respond T1110` consumes the same artefact and the evidence-led
investigation result to propose a dry-run-only, approval-gated response plan,
`duke validate T1110` proves the detection → investigation → response pipeline
with an ordered 19-case deterministic validation suite, and `duke report T1110`
renders a deterministic advisory report aggregating all of it. See
[the response documentation](../responses/T1110-safe-response.md),
[the validation documentation](../validation/T1110-detection-validation.md),
and [the reporting documentation](../reporting/T1110-incident-reporting.md).
Guided learning for T1110 is not yet implemented and fails safely with exit
code 2 through the registry's missing-capability path. See
the [T1110 lab overview](../labs/T1110/overview.md).

## References

- MITRE ATT&CK — T1110 Brute Force (https://attack.mitre.org/techniques/T1110/),
  T1110.003 Password Spraying (https://attack.mitre.org/techniques/T1110/003/)
- [T1110 lab documentation](../labs/T1110/overview.md)
- [T1110 response documentation](../responses/T1110-safe-response.md)
- [T1110 validation documentation](../validation/T1110-detection-validation.md)
- [T1110 reporting documentation](../reporting/T1110-incident-reporting.md)
- [Architecture Decision Records](../decisions/)

## Last reviewed

2026-09-26
