# 0003 — Safe, Synthetic Simulations

## Status

Accepted

## Context

Duke teaches detection, investigation, and response by simulating
adversary behaviour mapped to MITRE ATT&CK techniques. Some of these
techniques (e.g. T1078 — Valid Accounts) describe behaviour that, if
implemented literally, would require real credential misuse,
persistence mechanisms, or interaction with real security controls.
Implementing that behaviour for real would create real security risk
for anyone running Duke, and would be inappropriate for an education
platform intended to run in ordinary development and lab
environments without special isolation or authorization.

At the same time, Duke's value depends on producing realistic,
behaviourally accurate telemetry and scenarios so that the detection
and investigation skills learners build transfer to real
environments.

## Decision

Duke uses MITRE ATT&CK as a behavioural taxonomy for scenario design,
not as a source of attack scripts to implement. For every scenario,
Duke reproduces only the *observable effects* of adversary behaviour
using synthetic events, harmless files, temporary directories, and
isolated lab environments — never the underlying offensive
capability itself.

Duke will never implement: destructive malware or ransomware,
credential theft, uncontrolled persistence, security-product
disabling, real data exfiltration, unauthorized access, uncontrolled
exploitation, or code intended to evade real defensive systems.

Every simulation must:

- explain what is being simulated
- state what is intentionally not implemented
- use synthetic or disposable data
- avoid modifying real security settings
- support safe cleanup where applicable
- be suitable for an authorized training environment

## Consequences

- Learners can safely run Duke's simulations on their own machines
  or in shared lab environments without special authorization or
  isolation infrastructure.
- Detection logic is built and tested against normalized, synthetic
  telemetry that mirrors the *shape* of real events, which keeps
  detection design portable to real telemetry sources via adapters.
- Some scenarios will necessarily be simplified or approximated
  relative to real-world adversary tradecraft, since only observable
  effects — not full offensive capability — are reproduced.
- Every scenario carries a documentation burden to clearly state its
  safety classification and what is intentionally not implemented,
  so learners and reviewers can verify its boundaries.

## Alternatives Considered

- **Implement real offensive techniques in an isolated sandbox.**
  Rejected: shifts the burden of safe isolation onto every user's
  environment, raises the risk of misuse, and is unnecessary for
  teaching detection and response, which depend on realistic
  telemetry rather than genuine offensive capability.
- **Use only pre-recorded, static sample datasets with no
  simulation.** Rejected: static datasets can't adapt to learner
  actions, don't support interactive investigation and response
  workflows, and make it harder to vary scenario parameters for
  repeated practice.
- **Integrate with existing breach-and-attack-simulation (BAS)
  tools.** Rejected for the core: would introduce a vendor
  dependency into the core (see [ADR 0001](0001-vendor-agnostic-core.md))
  and shift safety guarantees onto third-party tooling outside
  Duke's control; may be revisited later as an optional adapter.
