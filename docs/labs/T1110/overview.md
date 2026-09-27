# T1110 Brute Force: Password Spraying

## Status

**Simulation, detection, investigation, response, and validation slice.**
This lab currently implements the safe, deterministic **simulation** of
ATT&CK T1110 — Brute Force (sub-technique **T1110.003 Password Spraying**), a
deterministic, explainable **detection** rule (`duke detect T1110`), an
evidence-led **investigation** (`duke investigate T1110`), safe, dry-run
**response planning** (`duke respond T1110`), and deterministic **detection
validation** (`duke validate T1110`, 19 cases). Reporting and guided learning
for T1110 are **intentionally not yet implemented**; those lifecycle commands
fail safely with exit code 2 through the registry's
missing-capability path until such slices land.

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
identify any actor as an attacker, or assert any impact. The detection rule
reports a **suspicious spray pattern**, and it explicitly states that
"compromise is not confirmed": a single successful authentication after
failures is supporting evidence only and does not prove that an account is
compromised — that determination belongs to later investigation, which is
not yet implemented for this scenario.

## Learning objectives

After completing the lab, a learner should be able to:

- recognise a password-spraying pattern by correlating many failed
  authentications with one later success;
- distinguish the brute-force (failed-login) pattern from the T1078
  valid-account pattern, which contains no failed logins;
- use typed Python models with success/failure event outcomes to generate
  and detect reproducible security telemetry;
- explain that the detection is a suspicious behavioural pattern without
  asserting compromise.

## Python concepts

- lists and tuples;
- functions and modules;
- type annotations;
- Pydantic models;
- timezone-aware datetimes;
- event outcomes (success vs failure);
- UUID generation;
- deterministic, evenly-spaced time offsets;
- sliding-window correlation and deterministic ranking;
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

## Run detection

Detection reads the normalized events exported by the simulation; it never
silently regenerates them, so it can be replayed against any exported
artefact.

```bash
duke simulate T1110 --output data/events/t1110-session-001.json
duke detect T1110 --input data/events/t1110-session-001.json
```

For the shipped corpus the rule produces a single finding
(`password-spraying-window`): **confidence 80 (high)**, tracing the six
failed authentications and the credited later success.

## Detection methodology

`duke detect T1110` infers a spray pattern purely from authentication
outcomes, never from an answer label. It is explainable and fully
deterministic:

- **Correlation key.** Events are grouped by acting source
  (`actor_entity_id`) — the entity performing the attempts.
- **Sliding 30-minute window.** Every failed authentication begins a
  candidate window; the contributing failures are those within
  `CORRELATION_WINDOW` (30 minutes) of that start. The **best qualifying
  window** is selected by: greatest distinct-account count, then greatest
  contributing failure count, then earliest window start, then deterministic
  event-ID ordering. This keeps an unrelated early failure from hiding a
  later valid spray burst.
- **Hard gate.** A window qualifies only when at least `MIN_DISTINCT_ACCOUNTS`
  (5) distinct accounts failed within it. A shared service target (present in
  every failure of the window) never counts as an account, and repeated
  failures against an already-counted account do not inflate the count.
- **Confidence.** The gate alone is worth `BASE_SPRAY_CONFIDENCE` (60), so a
  bare spray is still reported. Each distinct account beyond the threshold
  adds `EXTRA_ACCOUNT_POINTS` (5), capped at four. A later successful
  authentication from the same source to a previously-failed account (strictly
  after that account's failure and no later than the window end) adds
  `LATER_SUCCESS_POINTS` (15) as **supporting evidence only**. Confidence is
  capped at 100.
- **Severity.** Derived from confidence — 60–74 `medium`, 75–99 `high` —
  never `critical`, because investigation is not implemented and compromise
  is never confirmed.
- **Attribution.** `event_ids` trace every in-window failed authentication
  (including repeated attempts) plus any credited success, ordered by
  `occurred_at` then event ID. `entity_ids` implicate only the source and the
  distinct sprayed accounts; the shared service stays contextual.
- **Language.** The finding explicitly states "compromise is not confirmed"
  and describes a later success as supporting evidence only — it never asserts
  credential validity, compromise, attacker ownership, or impact.

For the shipped corpus: 6 distinct accounts (1 over the 5 threshold → +5) plus
the later success (+15) gives **confidence 80 → high**.

## Run investigation

Investigation reads the same artefact and works from the finding detection
already produced; it never reruns detection or rescans for a new pattern.

```bash
duke simulate T1110 --output data/events/t1110-session-001.json
duke investigate T1110 --input data/events/t1110-session-001.json
```

## Investigation methodology

`duke investigate T1110` (`investigate_t1110`) turns the existing finding and
its referenced telemetry into an evidence-led `InvestigationResult`. It is
fully deterministic and cautious:

- **Event boundary.** Only the events referenced by `finding.event_ids` are
  considered — it never searches the whole artefact. Events or entities
  referenced by the finding that cannot be resolved are skipped (never
  substituted with unrelated data), and an explicit incompleteness
  question/assessment is added when any are missing.
- **Evidence.** Every referenced failed authentication is `SUPPORTS`; a
  credited later success is `SUPPORTS` framed as "consistent with a credential
  having validated — supporting evidence, not proof of compromise." A shared
  authentication service is treated as context, never as an implicated account.
- **Timeline.** Listed by `occurred_at`, then event ID, preserving each source
  event's original target IDs (so a shared-service target may appear as event
  context) — it is never an involved entity.
- **Involved entities.** Resolved from `finding.entity_ids` only: the source
  and the distinct sprayed accounts. The shared service stays out.
- **Facts vs assessments.** Confirmed facts are strictly telemetry-derived
  (reported failure counts, resolved implicated targets, unresolved
  references, source-zone attributes). Interpretation — intent, credential
  validity, whether a success was legitimate — lives in analyst assessments.
- **Language.** No confirmed compromise, malicious attribution, credential
  theft, impact, or successful intrusion is ever asserted.

## Run response

Response reads the same artefact and works from the investigation result it
already produced; it never reruns detection or investigation and never
executes anything.

```bash
duke simulate T1110 --output data/events/t1110-session-001.json
duke respond T1110 --input data/events/t1110-session-001.json
```

## Response methodology

`duke respond T1110` (`plan_t1110_response`) builds a dry-run-only, approval-
gated `ResponsePlan` from the existing investigation result. It is fully
deterministic and cautious:

- **Plan-only.** Every action is `dry_run=True`, `requires_approval=True`,
  and `status=PLANNED`; nothing executes, contacts, or modifies a real
  system, account, sessions, credentials, MFA, permissions, or network.
- **Evidence-led targets.** The source is the unique actor across the
  finding-referenced events, intersected with the investigated entities; the
  success-associated account is the uniquely resolved finding-scoped
  `ACCOUNT` target of a referenced success. Ambiguous or unresolved targets
  cause the related targeted action to be omitted, and incomplete context is
  recorded in the incident summary. The shared portal is never targeted.
- **Proportionate and conditional.** Source containment is a temporary rate
  limit or challenge conditioned on ruling out shared NAT, proxy, authorized
  scanner, identity provider, or corporate egress — never an unconditional
  permanent block. Session revocation and credential rotation are conditional
  on a verified success-associated account and human review/approval.
- **Safe rollback.** Source throttle is reversible with removal criteria;
  session revocation is irreversible; credential rotation is irreversible and
  never restores prior credentials; preserved evidence is never deleted;
  review/monitoring actions have no rollback; the temporary step-up challenge
  is reversible only without weakening the baseline MFA/security
  requirements.
- **Non-asserting wording.** Only suspected password-spraying behaviour and
  possible credential validation are referenced; compromise, attribution,
  impact, and malicious intent are never confirmed.

## Run validation

Validation reads the same artefact and proves the detection → investigation →
response pipeline by rerunning it against controlled, in-memory mutations; it
never modifies the source artefact or input file.

```bash
duke simulate T1110 --output data/events/t1110-session-001.json
duke validate T1110 --input data/events/t1110-session-001.json
```

For the canonical corpus this reports **Validation complete: 19/19 cases
passed** and exits 0.

## Validation methodology

`duke validate T1110` (`validate_t1110`) runs an ordered 19-case catalogue.
Finding-producing cases assert an exact finding count, confidence, and
severity, run investigation and response, and verify every response action is
dry-run, approval-required, and `PLANNED`; no-finding cases stop after
detection and verify investigation and response were not invoked. All the
detector's hard boundaries are exercised: the five/four-account threshold,
repeated failures (counted once), shared-service exclusion, mixed source
actors, single-account guessing, an unrelated early failure, attempts split
beyond the window, and deterministic earliest-window selection between two
equal bursts. See
[the validation documentation](../../validation/T1110-detection-validation.md)
for the full case table.

## Intentionally not implemented yet

The following T1110 lifecycle commands fail **safely with exit code 2**
(they resolve the scenario, then report the missing capability before
touching any input):

```bash
duke report T1110 ...
duke learn T1110
```

Reporting and learning for T1110 are planned follow-on slices.

## Limitations

- The corpus is a single, fixed, deterministic timeline; it is not a
  high-rate simulation and does not vary lockout behaviour or password
  policy.
- The later success is modelled only as an authentication outcome; no
  follow-on activity (access, privilege, lateral movement) is simulated.
- **False positives:** a load-balanced or centralized authentication point
  that emits many failures from one apparent source IP in a short window, or
  an automated sync job hurt by a shared password, could trip the
  5-distinct/30-minute gate. The base of 60 (medium) keeps a bare spray
  low-severity so analysts can triage.
- **False negatives:** a slow, low-and-slow spray spread beyond 30 minutes,
  or a source that rotates per-attempt host identities (each source under the
  threshold), evades this single-source/window rule. This is out of scope for
  the current slice.
- The detection is tuned to the observable spray invariant (many distinct
  accounts, one source, one window), not to the specific synthetic account
  names or the portal UUID, so it generalizes to other data with or without a
  shared service target.

## References

- MITRE ATT&CK — [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/),
  [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [T1110 investigation documentation](../../investigations/T1110-password-spraying.md)
- [T1110 response documentation](../../responses/T1110-safe-response.md)
- [T1110 validation documentation](../../validation/T1110-detection-validation.md)
- [scenario-registry.md](../../scenarios/scenario-registry.md)
- [scenario-authoring.md](../../scenarios/scenario-authoring.md)
- [scenario-conformance.md](../../scenarios/scenario-conformance.md)
- [T1078 lab overview](../T1078/overview.md) — the complementary valid-account scenario
- [ROADMAP.md](../../../ROADMAP.md)

Last reviewed: 2026-09-26
