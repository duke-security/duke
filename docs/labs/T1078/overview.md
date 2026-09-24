# T1078 Valid Accounts: Compromised Identity

## Status

Simulation, detection, evidence-led investigation, safe dry-run response,
and deterministic detection validation implemented. Incident reporting
remains planned.

## Purpose

This lab demonstrates how a legitimate identity can produce a suspicious
behaviour sequence after apparent compromise. It focuses on observable
activity rather than credential theft or exploitation.

The scenario is mapped to MITRE ATT&CK T1078 — Valid Accounts and the
following tactics:

- Initial Access
- Persistence
- Privilege Escalation
- Defense Evasion

## Learning objectives

After completing the lab, a learner should be able to:

- explain why a successful login can still represent security risk;
- distinguish isolated events from suspicious behaviour sequences;
- correlate identity, device, application, file, privilege, and network
  telemetry;
- preserve evidence before proposing containment;
- propose dry-run-only, approval-gated response actions that can never
  modify a real system;
- use typed Python models to generate reproducible security telemetry.

## Python concepts

- lists, tuples, and dictionaries;
- functions and modules;
- type annotations;
- Pydantic models;
- timezone-aware datetimes;
- UUID generation;
- JSON and YAML serialization;
- deterministic test fixtures;
- file handling and overwrite protection.

## Synthetic entities

| Entity | Type | Purpose |
|---|---|---|
| Alex Morgan | Account | Synthetic user identity |
| workstation-017 | Host | Known compliant device |
| device-unknown-442 | Host | Unfamiliar unmanaged device |
| source-repository | Application | Internal code repository |
| deployment-notes.txt | File | Restricted synthetic file |
| privileged-access-service | Application | Synthetic privileged service |
| export-20260922.zip | File | Synthetic archive |
| 203.0.113.80:443 | Network connection | Documentation-only destination |

## Event timeline

| Sequence | Relative time | Action | Observation |
|---:|---:|---|---|
| 1 | 00:00 | `authenticate` | Known network, known device, MFA satisfied |
| 2 | 00:05 | `access_application` | Routine repository access |
| 3 | 08:00 | `authenticate` | New network, unfamiliar device, no MFA result |
| 4 | 08:02 | `enumerate_repository` | All projects enumerated |
| 5 | 08:04 | `read_file` | Restricted file accessed |
| 6 | 08:06 | `request_privileged_access` | Administrator role requested |
| 7 | 08:09 | `create_archive` | Fourteen synthetic items archived |
| 8 | 08:12 | `network_connect` | Five MiB sent to a documentation address |

No event contains an answer label such as `malicious`, `compromised`,
or `suspicious`. Detection logic must infer risk from the sequence and
context, and the implemented rule does exactly that.

## Run the simulation

```bash
duke simulate T1078
```

## Run detection

Detection reads the normalized events exported by the simulation; it
never silently regenerates them, so it can be replayed against any
exported artefact.

```bash
duke simulate T1078 --output data/events/t1078-session-001.json
duke detect T1078 --input data/events/t1078-session-001.json
duke investigate T1078 --input data/events/t1078-session-001.json
duke respond T1078 --input data/events/t1078-session-001.json
duke validate T1078 --input data/events/t1078-session-001.json
```

## Investigation

Investigation does not run detection itself. `duke investigate T1078`
loads the exported artefact, runs `detect_t1078`, and then passes the
existing `Finding` into `investigate_t1078`, which builds an evidence-led
result over the telemetry the finding references.

For the shipped T1078 corpus the investigation reports:

- **Involved entities** — Alex Morgan's account and the six implicated
  objects (unfamiliar device, repository, restricted file, privileged
  service, archive, external destination). The known-good baseline device
  (`workstation-017`) is treated as context and excluded.
- **Evidence** — one item per referenced event. The known-good baseline
  authentication is recorded as `PROVIDES_CONTEXT`; the new-context login
  and each follow-on behaviour are `SUPPORTS`.
- **Timeline** — the referenced events listed in ascending chronological
  order.
- **Confirmed facts** — evidence-grounded statements, e.g. that the
  account authenticated from a new network and unfamiliar device and that
  a restricted file was accessed.
- **Analyst assessments** — analytic interpretation, e.g. that the
  sequence is consistent with possible valid-account misuse (T1078) but
  does not confirm compromise.
- **Unresolved questions** — what remains open, e.g. whether the owner
  performed the activity and whether data was exfiltrated.

Investigation output is fully deterministic for a given artefact and
finding. When detection produces no finding, `duke investigate T1078`
reports "No findings to investigate" and exits 0.

See [the investigation documentation](../../investigations/T1078-compromised-identity.md)
for the full workflow.

## Dry-run response

`duke respond T1078` consumes the same artefact, re-runs detection and
investigation, and proposes a plan of dry-run-only response actions —
never executing any of them. See
[the response documentation](../../responses/T1078-safe-response.md) for
the full workflow.

```bash
duke respond T1078 --input data/events/t1078-session-001.json
```

The plan correlates the finding into a *preliminary* incident record and
groups proposed actions in a deliberate order:

- **Containment** — `disable-account`, `revoke-active-sessions`,
  `deny-unfamiliar-device`
- **Evidence preservation** — `preserve-telemetry-artefact`
- **Investigation follow-up** — `confirm-account-ownership`,
  `review-privileged-access-grant`, `assess-exfiltration-risk`
- **Recovery** — `require-mfa-reauthentication`,
  `rotate-account-credentials`

Every action is `dry_run=True`, `requires_approval=True`, and
`status=PLANNED`, and carries a purpose, risk, verification guidance, and
(where reversible) rollback guidance. Rollback is conservative: revoked
sessions and rotated credentials are not restorable, preserved evidence is
never deleted as rollback, and review-only actions have no rollback.
Containment and recovery actions are conditional recommendations grounded
in possible valid-account misuse — they never assert a confirmed
compromise or exfiltration. When detection produces no finding,
`duke respond T1078` reports "No findings to respond to" and exits 0.

Response is proposal-only: it modifies no real account, session,
permission, file, network, or security control.

## Detection validation

`duke validate T1078` proves the detection → investigation → response
pipeline behaves correctly by rerunning it against controlled, in-memory
mutations of the artefact. The source artefact is never modified (each
mutation copies events via immutable tuples and `model_copy`, and cloned
events get distinct deterministic IDs), no files are written, and no
network is touched. Sixteen explicit validation cases cover the unmodified
suspicious corpus, missing baseline, missing new-context login,
insufficient confidence, correlation-window expiry, wrong actor,
duplicate-behaviour non-inflation, the five individual follow-on removals,
benign activity, deterministic repeatability, evidence/timeline
traceability, and response-action dry-run safety. The suite's
`all_passed` flag is read-only and derived from its cases. When the
canonical corpus passes all 16 cases the command exits 0; an invalid
artefact or a failed suite exits 1; an unsupported technique exits 2.

See [the validation documentation](../../validation/T1078-detection-validation.md)
for the full case list.

## Detection methodology

`duke detect T1078` (`detection.compromised-identity-sequence`) infers
risk from behaviour and context, never from a labelled answer:

- **Known-good baseline (hard gate).** The rule only evaluates an
  identity that has a prior successful authentication from a *known*
  network and *known* device. New-context activity without that
  baseline produces no finding.
- **New-context login (25 points).** A later successful login from a
  *new* network and *unfamiliar* device anchors the evaluation.
- **Follow-on behaviours within 15 minutes.** Distinct behaviours by
  the same actor inside the window each add weight; duplicates are
  counted once:
  - repository enumeration — 10
  - restricted file access — 15
  - privileged-access request — 15
  - archive creation — 10
  - outbound network connection — 15
- **Confidence.** Points are summed, capped at 100, and a finding is
  emitted only at a confidence of 60 or more. A new-context login alone
  (25 points) can never reach the threshold.
- **Severity from confidence.** Confidence derives severity (medium at
  60–74, high at 75+). The rule never reports `critical`: although it
  is a high-confidence behavioural signal, Duke has not yet confirmed
  impact, exfiltration, or account compromise through investigation.

## Corpus finding

For the shipped T1078 corpus the rule produces a single finding:
**confidence 90 (high)** for the unfamiliar-device login plus all five
follow-on behaviours, linking the seven supporting events. The
implicated entities are Alex Morgan's account, the unfamiliar device,
the repository, the restricted file, the privileged-access service,
the archive, and the external destination. The known-good baseline
device (`workstation-017`) is treated as contextual and is deliberately
**not** implicated.

## Expected false positives

- A user who regularly works from an unmanaged personal device after an
  initial known-network login will match the core pattern and be scored
  based on what they actually do; heavy legitimate use can exceed 60.
- An operator bulking provisioning files from a new jump host could
  trigger the collection and privilege signals within the window.
- Any distinct behaviour that occurs inside the 15-minute window
  contributes weight, so a fast legitimate workflow can add up.
- Detection cannot yet distinguish a genuinely exfiltrating archive from
  an operator's backup; that distinction belongs to investigation.
