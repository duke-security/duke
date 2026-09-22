# T1078 Valid Accounts: Compromised Identity

## Status

Simulation implemented. Detection, investigation, response, validation,
and incident reporting remain planned.

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
or `suspicious`. Future detection logic must infer risk from the
sequence and context.

## Run the simulation

```bash
duke simulate T1078
