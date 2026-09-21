# 0001 — Vendor-Agnostic Core

## Status

Accepted

## Context

Duke is a cybersecurity education and security-engineering platform
that must model concepts spanning many real-world security products:
SIEMs, EDRs, identity providers, and cloud platforms (AWS, Azure,
GCP). Learners should be able to apply what they learn regardless of
which specific vendor tooling they encounter later, and Duke itself
must be able to add support for new vendors and platforms without
rewriting its core logic.

If vendor- or platform-specific concepts (log formats, APIs,
authentication models) leak into the core domain model, every future
integration would require changes throughout the codebase, and
learners would end up learning a specific vendor's abstractions
instead of transferable security-engineering concepts.

## Decision

Duke's core (`core`, `simulation`, `telemetry`, `detection`,
`investigation`, `response`, `reporting`, `labs`) will not depend
directly on any cloud provider, SIEM, EDR, or other security vendor.
All domain logic operates exclusively on Duke's own normalized
internal models (e.g. `SecurityEvent`, `Entity`, `Evidence`,
`Finding`, `Incident`, `ResponseAction`, `Scenario`).

Provider-specific behaviour and data formats are translated into
these normalized models exclusively through an `adapters` layer.
Adapters are optional and additive: Duke functions fully without any
adapter installed, using synthetic data and safe simulations.

## Consequences

- New vendor or platform support is added by writing a new adapter,
  without modifying core components.
- Core components can be developed, tested, and taught without
  requiring access to any real vendor product or credentials.
- An additional translation layer (adapters) is required for any
  real-world integration, which is a deliberate cost in exchange for
  portability and testability.
- Care is required during design and code review to prevent
  vendor-specific concepts from leaking into core models.

## Alternatives Considered

- **Build directly against a specific vendor stack (e.g. AWS +
  Splunk).** Rejected: would tie Duke's educational value to one
  vendor's specific tooling and make the platform unusable for
  learners and organizations using different products.
- **Support multiple vendors natively in the core with conditional
  logic.** Rejected: would couple core logic to every supported
  vendor's data model simultaneously, making the core harder to
  reason about, test, and extend as vendor support grows.
