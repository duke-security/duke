# T1110 — Safe Dry-Run Response: Password Spraying

## Overview

This document describes how Duke proposes a safe, dry-run-only response for
the T1110.003 Password Spraying scenario. It walks through the workflow
implemented by `duke respond T1110` (`plan_t1110_response`) and records the
proposed actions, their ordering, and the approval, verification, and
rollback behaviour that governs each one.

Response in Duke is **plan-only**. It never executes an action against a
real system. There is no code path that contacts an identity provider, a
device, a network, a file system (beyond reading the input artefact), or a
security control.

## Workflow

```bash
duke simulate T1110 --output data/events/t1110-session-001.json
duke detect T1110 --input data/events/t1110-session-001.json
duke investigate T1110 --input data/events/t1110-session-001.json
duke respond T1110 --input data/events/t1110-session-001.json
```

`duke respond T1110` loads the exported artefact, runs `detect_t1110` to
obtain a `Finding`, runs `investigate_t1110` to obtain an
`InvestigationResult`, and passes both into `plan_t1110_response`. The
planner returns a `ResponsePlan` containing:

1. a deterministic preliminary `Incident` correlation record;
2. the original `Finding`;
3. proposed `ResponseAction` records grouped by category — immediate
   containment, evidence preservation, investigation follow-up, and recovery
   recommendations.

## The preliminary incident

`ResponseAction` requires an `incident_id`. The planner therefore correlates
the finding into a deterministic preliminary `Incident` record. This record
exists **solely** so each proposed action can carry an `incident_id`; it does
not assert a confirmed compromise, attribution, impact, or final incident
report. Its summary records correlation only and states that compromise is
not confirmed.

## Evidence-led target selection

Targets are never hardcoded and never guessed. They are resolved strictly
from the finding and the investigation result:

- **Source** — the unique `actor_entity_id` across the finding-referenced
  events, intersected with the investigated entities. If there is not exactly
  one consistent, resolved source, source containment is omitted and the plan
  records incomplete or ambiguous context.
- **Success-associated account** — the uniquely resolved, finding-scoped
  `ACCOUNT` target of a referencing successful authentication. If there is
  not exactly one unambiguous account, session revocation, credential
  rotation, and account-specific step-up actions are omitted.
- **Sprayed accounts** — the finding-scoped accounts, used for review and
  monitoring.

No targeted containment or recovery action is ever proposed with an
unresolved `target_entity_id`; review, monitoring, and evidence-preservation
actions may legitimately carry no target.

## Proposed actions and ordering

Proposed actions are grouped and printed in this deliberate order — contain
first, preserve evidence, investigate, then recommend recovery. For the
shipped corpus (one source, six sprayed accounts, one later success against
`svc.reports`) every category below is populated.

### 1. Immediate containment

| Action | Target | Risk | Rollback |
|---|---|---|---|
| `temporarily-rate-limit-source` | the source | medium | Remove only after the source is confirmed authorized or benign; removal must not weaken existing controls or leave suspected accounts without required protections. |
| `revoke-active-sessions` | the success-associated account | medium | Irreversible — revoked sessions cannot be restored. Review required before any approval. |

### 2. Evidence preservation

| Action | Target | Risk | Rollback |
|---|---|---|---|
| `preserve-telemetry-artefact` | none | low | Irreversible — preserved evidence is never deleted as rollback. |

### 3. Investigation follow-up

| Action | Target | Risk | Rollback |
|---|---|---|---|
| `confirm-source-authorized` | the source (or none) | low | None — review changes no system state. |
| `review-sprayed-account-activity` | none | low | None — review of the finding-scoped accounts. |
| `assess-failure-cause` | none | low | None — analysis only; intent not asserted. |
| `monitor-for-further-spray` | none | low | None — monitoring only. |

### 4. Recovery recommendations (conditional, for the verified success account)

| Action | Target | Risk | Rollback |
|---|---|---|---|
| `apply-temporary-step-up-authentication` | the success-associated account | medium | A temporary, reversible challenge; restore the prior policy only if doing so does not weaken the organization's baseline MFA or security requirements. |
| `rotate-account-credentials` | the success-associated account | high | Irreversible — prior potentially exposed credentials are never restored. |

## Approval, verification, and rollback behaviour

Every proposed action is:

- `dry_run=True` — it only records what would happen;
- `requires_approval=True` — a human must approve before anything runs;
- `status=PLANNED` — no proposed action is ever in a runnable state.

Every action carries a `purpose` (rationale), a `risk` level,
`verification_guidance` (how a human would confirm the effect), and — where
reversible — `rollback_guidance` (documented by the model so no action
claims to be reversible without a real rollback path).

Rollback semantics are deliberately conservative:

- the source throttle supports rollback with an explicit removal criterion
  that must not weaken existing controls or leave suspected accounts without
  required protections;
- sessions that are revoked are not described as restorable;
- preserved evidence is never described as deletable as rollback;
- review-only, monitoring, and evidence-collection actions leave nothing to
  reverse, so they have no rollback guidance;
- credentials that may have been exposed are never restored;
- the temporary step-up challenge is reversible only in a way that never
  weakens the organization's baseline MFA / security requirements.

## Conditional, proportionate, non-asserting wording

Containment and recovery actions are framed as **conditional
recommendations** grounded in *suspected password-spraying behaviour*, not
as instructions that assert hostile intent. Source containment explicitly
accounts for shared NATs, proxies, authorized scanners, identity providers,
and corporate egress — it is never an unconditional permanent block.
Verification guidance confirms intended defensive effects while noting that
the absence of further alerts is not, by itself, proof of safety. No action
claims a confirmed compromise, attribution, impact, or malicious intent.

## Handling incomplete or ambiguous context

When events or entities referenced by the finding cannot be resolved, or the
source or success-associated account is ambiguous, the plan:

- never substitutes unrelated artefact objects;
- omits unsafe targeted actions whose target cannot be uniquely resolved;
- retains a deterministic plan with all four ordered categories (a category
  may be empty when nothing can be safely targeted); and
- explicitly records the incomplete/ambiguous context in the preliminary
  incident summary.

## Safety boundaries

`duke respond T1110` produces proposals only. It performs no access to or
modification of real accounts, sessions, permissions, files (other than
*reading* the exported artefact), networks, or security controls; it never
blocks addresses, rotates credentials, alters MFA, or contacts users. There
are no response adapters, no automatic approval, and no execution engine in
this slice.

## CLI output and exit codes

The command prints the incident, the finding, and the grouped actions with
their risk, approval, verification, and rollback guidance, followed by an
explicit banner that no real system was modified. Exit codes match the other
stages:

- `0` — a response plan was proposed, **or** the artefact produced no
  finding (`No findings to respond to`);
- `1` — invalid artefact (missing file, malformed JSON, unsupported schema
  version, or invalid entity/event record);
- `2` — unsupported technique.

## Limitations

- Response is proposal-generation only; execution, enforcement, and automatic
  approval are intentionally not implemented.
- The preliminary incident is a correlation record, not a confirmed incident
  or a final incident report.
- Source containment and account recovery remain conditional and require
  human verification before any enforcement.
- Rollback and verification guidance is descriptive; nothing is performed
  automatically.

## References

- MITRE ATT&CK — T1110 Brute Force (https://attack.mitre.org/techniques/T1110/),
  T1110.003 Password Spraying (https://attack.mitre.org/techniques/T1110/003/)
- [T1110 lab documentation](../labs/T1110/overview.md)
- [T1110 investigation documentation](../investigations/T1110-password-spraying.md)
- [Architecture Decision Records](../decisions/)

## Last reviewed

2026-09-26
