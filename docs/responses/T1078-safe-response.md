# T1078 — Safe Dry-Run Response: Compromised Identity

## Overview

This document describes how Duke proposes a safe, dry-run-only response
for the T1078 Valid Accounts scenario. It walks through the workflow
implemented by `duke respond T1078` (`plan_t1078_response`) and records
the proposed actions, their ordering, and the approval, verification, and
rollback behaviour that governs each one.

Response in Duke is **plan-only**. It never executes an action against a
real system. There is no code path that contacts an identity provider, a
device, a network, a file system (beyond reading the input artefact), or a
security control.

## Workflow

```bash
duke simulate T1078 --output data/events/t1078-session-001.json
duke detect T1078 --input data/events/t1078-session-001.json
duke investigate T1078 --input data/events/t1078-session-001.json
duke respond T1078 --input data/events/t1078-session-001.json
```

`duke respond T1078` loads the exported artefact, runs `detect_t1078` to
obtain a `Finding`, runs `investigate_t1078` to obtain an
`InvestigationResult`, and passes both into `plan_t1078_response`. The
planner returns a `ResponsePlan` containing:

1. a deterministic preliminary `Incident` correlation record;
2. the original `Finding`;
3. proposed `ResponseAction` records grouped by category:
   immediate containment, evidence preservation, investigation follow-up,
   and recovery recommendations.

## The preliminary incident

`ResponseAction` requires an `incident_id`. The planner therefore
correlates the finding into a deterministic preliminary `Incident` record.
This record exists **solely** so each proposed action can carry an
`incident_id`; it does not assert a confirmed compromise or exfiltration
and is not a final incident report. Its summary states that it records
correlation only and that impact and account state are not asserted.

## Proposed actions and ordering

Proposed actions are grouped and printed in this deliberate order —
contain first, preserve evidence, investigate, then recommend recovery.

### 1. Immediate containment

| Action | Target | Risk | Rollback |
|---|---|---|---|
| `disable-account` | the account | high | Re-enable only after ownership and access safety are verified. |
| `revoke-active-sessions` | the account | medium | Irreversible — revoked sessions cannot be restored. Issuing a new session is recovery, not rollback. |
| `deny-unfamiliar-device` | the unfamiliar device | medium | Re-allow only after device ownership and security posture are verified. |

### 2. Evidence preservation

| Action | Target | Risk | Rollback |
|---|---|---|---|
| `preserve-telemetry-artefact` | none | low | Irreversible — deleting preserved evidence is not rollback and is never recommended as one. |

### 3. Investigation follow-up

| Action | Target | Risk | Rollback |
|---|---|---|---|
| `confirm-account-ownership` | the account | low | None — review alone changes no system state. |
| `review-privileged-access-grant` | the privileged service | medium | None — review alone makes no change; a role is not described as restorable unless the action revokes one. |
| `assess-exfiltration-risk` | the external destination | low | None — correlation analyses risk and does not assume data was exfiltrated. |

### 4. Recovery recommendations

| Action | Target | Risk | Rollback |
|---|---|---|---|
| `require-mfa-reauthentication` | the account | medium | Restore the previous access policy only after explicit review, and never weaken baseline MFA requirements. |
| `rotate-account-credentials` | the account | high | Irreversible — prior potentially exposed credentials are never restored. |

## Approval, verification, and rollback behaviour

Every proposed action is:

- `dry_run=True` — it only records what would happen;
- `requires_approval=True` — a human must approve before anything runs;
- `status=PLANNED` — no proposed action is ever in a runnable state.

Every action carries a `purpose` (rationale), a `risk` level,
`verification_guidance` (how a human would confirm the effect), and —
where reversible — `rollback_guidance` (documented by the model so no
action claims to be reversible without a real rollback path).

Rollback semantics are deliberately conservative:

- sessions that are revoked are not described as restorable;
- preserved evidence is never described as deletable as rollback;
- review-only actions have no rollback guidance, since making no change
  leaves nothing to reverse;
- credentials that may have been exposed are never restored.

## Conditional, non-asserting wording

Containment and recovery actions are framed as **conditional
recommendations** grounded in *possible valid-account misuse* — not as
instructions that assert a compromise occurred. Investigation follow-up
steps analyse risk and *do not assume* data was exfiltrated. No action
claims a confirmed compromise or confirmed exfiltration.

## Safety boundaries

`duke respond T1078` produces proposals only. It performs no access to or
modification of real accounts, sessions, permissions, files (other than
*reading* the exported artefact), networks, or security controls. There
are no response adapters, no automatic approval, and no execution engine
in this slice.

## CLI output and exit codes

The command prints the incident, the finding, and the grouped actions with
their risk, approval, verification, and rollback guidance, followed by an
explicit banner that no real system was modified. Exit codes match the
other stages:

- `0` — a response plan was proposed, **or** the artefact produced no
  finding (`No findings to respond to`);
- `1` — invalid artefact (missing file, directory, malformed JSON,
  unsupported schema version, or invalid entity/event record);
- `2` — unsupported technique.

## Limitations

- Response is proposal-generation only; execution, enforcement, and
  automatic approval are intentionally not implemented.
- The preliminary incident is a correlation record, not a confirmed
  incident or a final incident report.
- Rollback and verification guidance is descriptive; nothing is performed
  automatically.

## References

- MITRE ATT&CK — T1078 Valid Accounts (https://attack.mitre.org/techniques/T1078/)
- [T1078 lab documentation](../labs/T1078/overview.md)
- [T1078 investigation documentation](../investigations/T1078-compromised-identity.md)
- [T1078 detection validation documentation](../validation/T1078-detection-validation.md)
- [Architecture Decision Records](../decisions/)

## Last reviewed

2026-09-23
