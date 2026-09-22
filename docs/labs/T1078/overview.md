# T1078 Valid Accounts: Compromised Identity

## Status

Simulation and detection implemented. Investigation, response,
validation, and incident reporting remain planned.

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
```

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
