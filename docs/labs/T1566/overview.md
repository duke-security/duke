# T1566 Overview — Phishing: Spearphishing Link (T1566.002)

This is the lab guide for Duke's **T1566 — Phishing** scenario, modelling the
**T1566.002 — Spearphishing Link** sub-technique.

> **Status: simulation complete; full lifecycle planned.** Only the safe,
> deterministic **simulation** slice of this scenario is implemented today.
> Detection, investigation, response, validation, reporting, and guided
> learning are **planned** and are **not** yet implemented. This document
> covers the completed simulation and the *planned* defensive workflow that
> will follow.

Duke registers this scenario with canonical technique ID **T1566** and
accepts **T1566.002** as an alias (the same pattern used for T1110 and
T1110.003). The behaviour modelled is specifically **Spearphishing Link**.

## Learning objectives

- Reconstruct the observable telemetry chain of a spearphishing-link attempt:
  delivery → open → click → inert redirect record → DNS-style observation →
  defensive web-filter block.
- Recognise that a click or redirect record is evidence of *observed UI and
  telemetry activity*, never proof that a real connection completed or that an
  account was compromised.
- Explain the difference between the Initial Access / social-engineering
  entry vector (T1566) and the credential-access and valid-account patterns
  modelled by T1110 and T1078.

## Required Python knowledge

Simulation authors use deterministic, typed models and datetime arithmetic.
This lab assumes comfort with:

- Lists and tuples
- Functions and modules
- Typed data models (Pydantic)
- Datetime arithmetic with timezone-aware timestamps
- Event outcomes (success vs unknown)
- Deterministic test data

## Security scenario

A synthetic employee receives a spearphishing email whose message contains a
link to an inert, RFC 2606 reserved domain (`example.invalid`). The employee
opens the message and clicks the link. An inert redirect record is produced,
correlated DNS-style telemetry is observed with an inconclusive outcome, and
a defensive web filter blocks the reserved destination.

## Threat relevance

Spearphishing links are one of the most common Initial Access vectors across
current threat actors. Detecting the *observable* chain — delivery of an
untrusted message, the click, the redirect, the DNS activity, and the
defensive block — is the foundation of a phishing detection pipeline that
does not depend on any single vendor's mail or web filter.

## ATT&CK mapping

| Field | Value |
|---|---|
| Technique | T1566 — Phishing |
| Sub-technique | T1566.002 — Spearphishing Link |
| Tactic | Initial Access |
| Registry ID | `T1566` (canonical) |
| Alias | `T1566.002` |

## Safety boundaries

- Uses only synthetic identities, hosts, and RFC 2606 reserved
  (`example.invalid`) domains.
- Never delivers, opens, or clicks a real email or link.
- Never makes a real network request, resolves a real domain, or fetches
  content.
- Contains no payload, attachment, macro, or credential-harvesting page, and
  never collects or stores credentials.
- Click, redirect, and DNS records never imply a completed connection; the
  block is a defensive policy decision only.
- Never labels the employee as compromised, the message as an attacker, or
  asserts any impact.

## Generated telemetry (implemented)

The simulation produces exactly **five entities** and **six ordered events**:

| # | action | outcome | summary |
|---|---|---|---|
| 1 | `email_receive` | success | Synthetic message delivered to the employee |
| 2 | `email_open` | success | Employee opens the message |
| 3 | `url_click` | success | Employee clicks the link (recorded UI action only) |
| 4 | `url_redirect` | success | Inert redirect telemetry record (`destination_reached=false`) |
| 5 | `dns_query` | unknown | Inconclusive DNS-style observation (`resolved=false`) |
| 6 | `url_blocked` | success | Defensive web-filter block (policy decision; `established=false`) |

No event asserts compromise, credential theft, payload execution, malware,
impact, or completed network access.

## Detection methodology (planned)

Detection for T1566.002 is **planned** and is not implemented in this slice.
The intended methodology will be behaviour-based and vendor-neutral, mirroring
the approach used for T1078 and T1110. It must operate only on event shape and
relationship structure, and must **not** depend on any fixed domain, entity
ID, name, or corpus value (the reserved `example.invalid` domain is purely a
safety device for the synthetic corpus, not a detection anchor):

- Correlate a generic delivery → open → click chain for a single actor
  (`email_receive`, `email_open`, `url_click`).
- Treat `url_redirect` and `dns_query` records as supporting or contextual
  evidence, never as completed network access or compromise.
- Weight the presence of a defensive block (`url_blocked`) on the same
  destination along the chain.
- The finding will derive an explainable confidence score from these generic
  behavioural signals and state explicitly that compromise is not confirmed.

## Expected false positives (planned)

A planned detection should weigh genuine benign behaviour — legitimate users
clicking links in unsolicited mail, or links in documentation or test
correspondence — and should never treat a single click, redirect, or
default-blocked destination as an incident on its own.

## Investigation workflow (planned)

Planned investigation will build an evidence-led timeline from the six events,
implicate only entities actually referenced, distinguish confirmed telemetry
facts from analyst assessments, and keep unresolved questions (e.g. whether
the recipient reported the message, whether the block was triggered by a
policy exemption).

## Supporting evidence (planned)

Planned investigation will cite per-event `Evidence` items with
`SUPPORTS`/`PROVIDES_CONTEXT` relationships, never asserting impact.

## Response methodology (planned)

Planned response will be a dry-run-only plan: guidance to report/quarantine
the message, brief the recipient, enforce the reserved-domain block policy,
and preserve telemetry — all approval-gated and never executed.

## Validation approach (planned)

Planned validation will rerun the detection pipeline against controlled
in-memory mutations of the artefact, never modifying the input file, and
report a read-only pass/fail suite.

## Hardening recommendations (planned)

- Enable reserved-domain blocking in mail and web filters.
- Support user reporting of suspected phish.
- Log link-click and DNS activity at the proxy and resolver for correlation.
- Avoid authorising single-user exceptions to the reserved-domain block.

## Limitations

- This slice implements **simulation only**. Click/redirect/DNS records are
  synthetic observations; no real network, email, or browsing occurred.
- Detection through learning are not yet implemented (see status above).

## References

- [MITRE ATT&CK T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
- [MITRE ATT&CK T1566.002 — Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [RFC 2606 — Reserved Top Level DNS Names](https://datatracker.ietf.org/doc/html/rfc2606)
- [`docs/decisions/0003-safe-synthetic-simulations.md`](../../decisions/0003-safe-synthetic-simulations.md)

Last reviewed: 2026-10-03
