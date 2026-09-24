# T1078 — Evidence-Led Investigation: Compromised Identity

## Overview

This document describes how to investigate the T1078 Valid Accounts
scenario evidence-led style. It walks through the workflow implemented by
`duke investigate T1078` (`investigate_t1078`) and records the supporting
evidence, the analytic reasoning, and the questions that remain open.

Investigation is deliberately separate from detection. `duke investigate`
loads a normalized telemetry artefact, runs `detect_t1078` to obtain a
`Finding`, and passes that existing `Finding` into the investigation logic.
Investigation never runs detection itself, so the two components stay
independently testable and reusable.

## Workflow

```bash
duke simulate T1078 --output data/events/t1078-session-001.json
duke detect T1078 --input data/events/t1078-session-001.json
duke investigate T1078 --input data/events/t1078-session-001.json
```

`duke investigate T1078` builds an `InvestigationResult` containing:

1. the original `Finding`;
2. the **involved entities** resolved from `Finding.entity_ids`;
3. one **`Evidence`** per event referenced by `Finding.event_ids`;
4. a chronological **`TimelineEntry`** per referenced event;
5. distinct **confirmed facts**, **analyst assessments**, and
   **unresolved questions**.

## Supporting evidence

Only the events referenced by the finding are considered, so every piece
of evidence traces back to a concrete event (`source_event_id`). Evidence
is classified by relationship:

- The **known-good baseline authentication** (known network, known device)
  is recorded as `PROVIDES_CONTEXT` — it explains why the later behaviour
  is out of character, but is not itself suspicious.
- The **new-context authentication** (new network, unfamiliar device) and
  every **follow-on behaviour** are recorded as `SUPPORTS`.

Deterministic evidence identifiers are derived from each referenced
event, so the same artefact and finding always produce the same evidence.

## Timeline

The timeline lists the referenced events in ascending chronological order.
For the shipped T1078 corpus, that is:

| Order | Observation |
|---:|---|
| 1 | Successful authentication from a known network and device (baseline) |
| 2 | Successful authentication from a new network and unfamiliar device |
| 3 | Repository enumeration |
| 4 | Restricted file access |
| 5 | Privileged-access request |
| 6 | Archive creation |
| 7 | Outbound network connection |

## Confirmed facts

Facts are evidence-grounded statements, not interpretation. For the shipped
corpus, the investigation confirms that:

- the account authenticated successfully from a known network and device;
- the account later authenticated successfully from a new network and
  unfamiliar device;
- repository content was enumerated;
- a restricted file was accessed;
- a privileged-access request was made;
- an archive was created;
- an outbound network connection was observed.

## Analyst assessments

Assessments are the analyst's interpretation of the facts:

- The new-context login followed by a correlated set of behaviours is
  consistent with possible valid-account misuse (MITRE ATT&CK T1078).
- This is a behavioural signal; impact, exfiltration, and account
  compromise are not confirmed by investigation alone.

## Unresolved questions

Questions remain open that a full incident response would need to answer:

- Did the account owner perform the new-context login and follow-on
  behaviours?
- Was any restricted file or archive exfiltrated during the session?
- Was the requested privileged access granted, and did it persist?

## How the investigation was detected

The finding that drives this investigation is produced by `detect_t1078`
(`compromised-identity-sequence`), which infers risk from the behaviour
sequence and context described in the
[T1078 lab documentation](../labs/T1078/overview.md) rather than from any
labelled answer.

## Safety boundaries

Investigation operates only on synthetic, deterministic telemetry produced
by `duke simulate`. It performs no access to real systems, no credential
handling, and no remediation. All data is from the exported JSON artefact.

## Limitations

- The investigation reports analysis, not a confirmed compromise.
- Unresolved questions require additional evidence that this slice does
  not attempt to collect.
- Only the events the finding references are surfaced; related but
  unreferenced telemetry is intentionally excluded.

## Next: response

Once an investigation result exists, `duke respond T1078` consumes the
same artefact and evidence-led result to propose a dry-run-only,
approval-gated response plan. See
[the response documentation](../responses/T1078-safe-response.md).

## References

- MITRE ATT&CK — T1078 Valid Accounts (https://attack.mitre.org/techniques/T1078/)
- [T1078 lab documentation](../labs/T1078/overview.md)
- [Architecture Decision Records](../decisions/)

## Last reviewed

2026-09-23
