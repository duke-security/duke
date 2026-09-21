# Core Domain Model

This document describes Duke's vendor-neutral core domain model,
implemented in `duke.core` as typed Pydantic v2 models. It is Stage 1
of the current milestone (see [ROADMAP.md](../../ROADMAP.md)): a
shared vocabulary that scenario simulation, telemetry, detection,
investigation, response, and reporting will all be built on top of.

None of these models depend on a cloud provider, operating system,
SIEM, or EDR. Provider-specific data is translated into these models
through an adapter — see
[ADR 0001](../decisions/0001-vendor-agnostic-core.md).

## Conventions

Every model follows the same conventions:

- **Identifiers.** Every model has a `id: UUID` field with a
  `default_factory` of `uuid4`, so constructing a model never requires
  the caller to invent an identifier.
- **Relationships by identifier.** Models reference each other by
  `UUID` (e.g. `Finding.event_ids`, `Incident.finding_ids`) rather
  than embedding one model inside another. The same event, piece of
  evidence, or entity is often relevant to several findings or
  incidents, and embedding would either duplicate data or force an
  artificial single owner.
- **Timezone-aware datetimes.** Every timestamp field uses Pydantic's
  `AwareDatetime` type, which rejects naive `datetime` values at
  validation time. Security telemetry is frequently correlated across
  systems in different timezones; a naive timestamp is a latent bug.
- **Enums over free text.** Fields with a small, well-known set of
  valid values use an enum (see below) instead of a string, so that
  invalid or inconsistent values are rejected at construction time
  rather than discovered downstream.
- **Unknown fields are rejected.** Every model sets
  `model_config = ConfigDict(extra="forbid")` (via the shared
  `DukeModel` base class). This keeps vendor- or tool-specific fields
  from silently leaking into the normalized core model; translating
  that data is an adapter's job, not the core model's.

## Enums

| Enum | Used by | Values |
|---|---|---|
| `EntityType` | `Entity` | `user`, `account`, `host`, `process`, `file`, `network_connection`, `cloud_resource`, `application` |
| `Severity` | `Finding`, `Incident` | `informational`, `low`, `medium`, `high`, `critical` |
| `EventOutcome` | `SecurityEvent` | `success`, `failure`, `unknown` |
| `EvidenceRelationship` | `Evidence` | `supports`, `contradicts`, `provides_context` |
| `FindingStatus` | `Finding` | `new`, `under_review`, `confirmed`, `false_positive`, `closed` |
| `IncidentStatus` | `Incident` | `open`, `investigating`, `contained`, `eradicated`, `recovered`, `closed` |
| `ResponseStatus` | `ResponseAction` | `planned`, `pending_approval`, `approved`, `in_progress`, `completed`, `failed`, `rolled_back`, `rejected` |
| `ResponseRisk` | `ResponseAction` | `low`, `medium`, `high` |

## Models

### `Entity`

A vendor-neutral actor or object observed in security telemetry — a
user, host, process, file, network connection, cloud resource, or
application. Entities are referenced by `id` from events, findings,
and incidents rather than duplicated, since the same entity is
typically involved in many of them. `identifier` holds a stable
natural identifier (a username, hostname, IP address, ARN, ...);
`attributes` holds additional normalized key-value context that does
not yet justify a first-class core field. Adapters must translate
vendor-specific names and values before placing data here.

### `SecurityEvent`

A single normalized observation of activity — *what was observed*,
independent of any cloud provider, operating system, SIEM, or EDR.
Provider-specific telemetry (a CloudTrail record, a Windows event log,
an EDR alert, ...) must be translated into this shape by an adapter
before it reaches Duke's core. An event records `action` (a normalized
verb, e.g. `authenticate` or `process_create`), `outcome`, `source`
(a normalized category of the telemetry's origin, e.g.
`identity_provider`, never a vendor name), and optionally the actor
and target `Entity` identifiers involved.

Example — a successful authentication from an unfamiliar location,
normalized regardless of which identity provider produced it:

```json
{
  "id": "a1b2c3d4-0000-4000-8000-000000000001",
  "occurred_at": "2026-01-15T03:42:10Z",
  "action": "authenticate",
  "outcome": "success",
  "source": "identity_provider",
  "actor_entity_id": "a1b2c3d4-0000-4000-8000-000000000002",
  "target_entity_ids": [],
  "attributes": {
    "mfa_used": "false",
    "source_ip": "203.0.113.5",
    "source_geo": "unfamiliar_country"
  }
}
```

### `Evidence`

A single piece of evidence used to reason about a finding or incident.
Evidence must trace back to something concrete: either a
`SecurityEvent` (`source_event_id`) or a non-event artefact such as a
file hash or log excerpt (`source_artifact_reference`). A model
validator enforces that at least one of the two is set — evidence that
cannot be traced back to anything is not evidence. `relationship`
(`EvidenceRelationship`) records whether this evidence supports,
contradicts, or merely provides context for the assessment it
informs, since not all evidence gathered during an investigation
corroborates the working hypothesis.

### `Finding`

A single detection result: that some detection logic fired, why it
fired (`detection_name` and `detection_details`), and — by
identifier — the events, evidence, and entities that support it.
`severity` and `status` (`FindingStatus`) track the finding's own
lifecycle independently of any incident it may later be correlated
into. `technique_id` optionally records an associated MITRE ATT&CK
technique.

### `Incident`

A correlated set of findings tracked as a single security incident.
An incident must correlate at least one `Finding` (`finding_ids`) and
affect at least one `Entity` (`affected_entity_ids`) — both fields
require a minimum length of one, since an incident with neither is
not yet an incident. `evidence_ids` lets an incident accumulate
evidence gathered directly during investigation, in addition to
whatever evidence each correlated finding already references.
`status` (`IncidentStatus`) follows a NIST-style incident lifecycle
from `open` through `closed`.

### `ResponseAction`

A single response action taken, or proposed, against an incident.
Every field exists to support safe, auditable response: `purpose`
(why it's being taken), `risk` (`ResponseRisk`), `requires_approval`
(whether a human must sign off before it runs), `dry_run` (whether it
only simulates its effect), `status` (`ResponseStatus`),
`verification_guidance` (how to confirm it worked), and
`supports_rollback` with `rollback_guidance`. A model validator
requires `rollback_guidance` whenever `supports_rollback` is `True` —
a reversible action without documented rollback steps is not
actually safely reversible.

### `Scenario`

Metadata describing a single guided learning scenario: its ATT&CK
technique and tactic, `learning_objectives`, `python_concepts`,
`telemetry_requirements`, `safety_notes`, `version`, and
`last_reviewed` date. `learning_objectives`, `python_concepts`, and
`safety_notes` each require at least one entry. `Scenario` is metadata
only — it does not embed simulation, detection, or response logic;
those will be built as separate, testable components that a scenario
composes.

## What this stage deliberately does not include

Per the current milestone (see [ROADMAP.md](../../ROADMAP.md) and
[AGENTS.md](../../AGENTS.md)), this stage adds only the core domain
model. It does not add cloud adapters, scenario simulation logic,
detection rules, persistence, an API, or a GUI. Those are built as
separate, independently testable components on top of these models.
