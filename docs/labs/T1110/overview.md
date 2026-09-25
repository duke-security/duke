# T1110 Brute Force: Password Spraying

## Status

**Simulation slice only.** This lab currently implements the safe,
deterministic **simulation** of ATT&CK T1110 — Brute Force (sub-technique
**T1110.003 Password Spraying**). Detection, evidence-led investigation,
safe dry-run response, validation, reporting, and guided learning for T1110
are **intentionally not yet implemented**; lifecycle commands for T1110
fail safely with exit code 2 through the registry's missing-capability path
until those slices land.

## Purpose

This lab demonstrates the *observable* telemetry of a password-spraying
behaviour: many failed authentications against distinct accounts from a
single external source, followed by one later success. It focuses on
**what a defensive system would observe** — repeated authentication
failures and a subsequent success — rather than performing real attempts
or implementing offensive capability.

The scenario is mapped to MITRE ATT&CK **T1110 — Brute Force** under the
**Credential Access** tactic, and specifically to sub-technique
**T1110.003 — Password Spraying**.

## Why password spraying

Password spraying spreads a small number of likely passwords across many
accounts to avoid lockouts, making it a common real-world initial-access
pattern. Its observable signature — a burst of `FAILURE` authentications
against several accounts from one source, then a success — is distinctive
without requiring any credential value or real attempt. The distant
alternatives (T1110.001 Password Guessing, T1110.002 Password Cracking,
T1110.004 Credential Stuffing) model either single-account focus, offline
activity with sparse telemetry, or known breached credential lists; the
spray variant is both the safest and the most detectable to model.

## Caution about language

The synthetic telemetry confirms only that individual authentications
succeeded or failed. It does **not** label any account as compromised,
identify any actor as an attacker, or assert any impact. A single
successful authentication after failures is **suspicious** and a suitable
anchor for a future detection rule, but success alone does **not** prove
that an account is compromised — that determination belongs to later
investigation, which is not yet implemented for this scenario.

## Learning objectives

After completing the lab, a learner should be able to:

- recognise a password-spraying pattern by correlating many failed
  authentications with one later success;
- distinguish the brute-force (failed-login) pattern from the T1078
  valid-account pattern, which contains no failed logins;
- use typed Python models with success/failure event outcomes to generate
  reproducible security telemetry;
- explain that the sequence is suspicious without asserting compromise.

## Python concepts

- lists and tuples;
- functions and modules;
- type annotations;
- Pydantic models;
- timezone-aware datetimes;
- event outcomes (success vs failure);
- UUID generation;
- deterministic, evenly-spaced time offsets;
- JSON serialization and overwrite protection.

## Threat relevance

Password spraying is a widespread, high-volume credential-access technique
used by both commodity and sophisticated actors against internet-facing
services. Detecting the many-failures-then-success signature at the identity
provider is a foundational detection engineering exercise and pairs with
the T1078 valid-account scenario as the natural "failed attempt" counterpart.

## Safety boundaries

- Uses only synthetic identities, hosts, and **RFC 5737 documentation-range**
  IP addresses (`198.51.100.77` for the external source, `203.0.113.10` for
  the benign baseline).
- Does **not** perform or attempt real authentication.
- Does **not** store, generate, describe, or imply any real password or
  credential value — only the observable outcome label
  `failure_reason="invalid_credentials"` appears.
- Does **not** make real network connections, spawn subprocesses, or touch
  the filesystem during generation (pure in-memory data).
- Does **not** label any account as compromised or any actor as an attacker.
- Does **not** modify accounts, permissions, sessions, or security controls.

## Generated telemetry

Entities (10): the benign user account `r.morales`, its known host
`workstation-008`, the external spray source `host-198.51.100.77`, the
targeted `web-portal`, and six distinct target accounts
(`svc.integration`, `svc.reports`, `svc.analytics`, `svc.etl`,
`d.garcia`, `a.okafor`).

Events (8), all `source="identity_provider"`, exact deterministic offsets
from a fixed start time:

| # | Offset | Outcome | Actor → Target | Notes |
|---:|---:|---|---|---|
| 1 | 00:00 | success | `r.morales` → `workstation-008` | Benign baseline |
| 2 | 12:00 | failure | spray source → `web-portal`, `svc.integration` | Spray round, account 1 |
| 3 | 12:02 | failure | spray source → `web-portal`, `svc.reports` | Account 2 |
| 4 | 12:04 | failure | spray source → `web-portal`, `svc.analytics` | Account 3 |
| 5 | 12:06 | failure | spray source → `web-portal`, `svc.etl` | Account 4 |
| 6 | 12:08 | failure | spray source → `web-portal`, `d.garcia` | Account 5 |
| 7 | 12:10 | failure | spray source → `web-portal`, `a.okafor` | Account 6 |
| 8 | 12:12 | success | spray source → `web-portal`, `svc.reports` | Later success |

Failures are **evenly spaced two minutes apart**; the later success follows
the failure sequence 12 minutes after spraying begins. The pattern is a
short, spaced burst, not a prolonged high-rate flood. No event carries an
answer label such as `malicious`, `compromised`, or `suspicious`.

The account that later succeeds (`svc.reports`) is one of the previously
sprayed accounts, and the success comes from the same external source and
new/unknown context. This is the analytic anchor: the sequence is
**suspicious** and suitable for later detection, but the success alone does
**not** prove account compromise.

## Run the simulation

```bash
duke simulate T1110 --output data/events/t1110-session-001.json
```

Resolution also works via the slug (`t1110_brute_force`), the friendly alias
(`brute-force`), and the sub-technique alias (`T1110.003`). The exported
artefact uses schema version `1.0` and round-trips through the existing
telemetry loader unchanged.

## Intentionally not implemented yet

The following T1110 lifecycle commands fail **safely with exit code 2**
(they resolve the scenario, then report the missing capability before
touching any input):

```bash
duke detect T1110 ...
duke investigate T1110 ...
duke respond T1110 ...
duke validate T1110 ...
duke report T1110 ...
duke learn T1110
```

Detection, investigation, response, validation, reporting, and learning for
T1110 are planned follow-on slices. Until then, the fingerprint of this
scenario for a future detector would be: one benign baseline success, six
distinct failing accounts from a single external source, and one later
success against a previously targeted account.

## Limitations

- The corpus is a single, fixed, deterministic timeline; it is not a
  high-rate simulation and does not vary lockout behaviour or password
  policy.
- The later success is modelled only as an authentication outcome; no
  follow-on activity (access, privilege, lateral movement) is simulated.
- No false-positive analysis is possible yet because detection is not
  implemented; that belongs to a later slice.

## References

- MITRE ATT&CK — [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/),
  [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [scenario-registry.md](../../scenarios/scenario-registry.md)
- [scenario-authoring.md](../../scenarios/scenario-authoring.md)
- [scenario-conformance.md](../../scenarios/scenario-conformance.md)
- [T1078 lab overview](../T1078/overview.md) — the complementary valid-account scenario
- [ROADMAP.md](../../../ROADMAP.md)

Last reviewed: 2026-09-25
