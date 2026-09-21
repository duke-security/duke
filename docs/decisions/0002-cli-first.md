# 0002 — CLI-First Interface

## Status

Accepted

## Context

Duke needs a primary interface through which learners run lessons,
trigger simulations, inspect telemetry, and work through detection,
investigation, and response workflows. Security engineers overwhelmingly
work in terminals — against SIEMs, EDRs, and cloud consoles that all
expose CLI or shell-adjacent workflows — so a command-line interface
is also the most representative teaching environment for the skills
Duke aims to build. Building an API, TUI, or web interface first
would add substantial design and implementation surface area before
any core capability exists to expose.

## Decision

Duke builds its command-line interface first, using
[Typer](https://typer.tiangolo.com/) for command definition and
[Rich](https://rich.readthedocs.io/) for terminal output. All new
capabilities (simulation, telemetry, detection, investigation,
response, reporting, labs) are exposed through the CLI as they are
implemented. An API, TUI, or web interface may be considered later,
but only once justified by concrete needs, and would be built on top
of the same core components the CLI uses — never as a replacement
for the core/CLI separation.

## Consequences

- Every capability must have a clear, typed, testable CLI entry
  point, which keeps the command surface deliberate rather than
  sprawling.
- Learners get a realistic, terminal-based workflow that mirrors
  real security-engineering tooling.
- A future API, TUI, or web interface reuses the same core logic as
  the CLI rather than duplicating it, since business logic lives in
  core components, not in CLI command handlers.
- Some interaction patterns that are easier in a GUI (e.g. graph
  exploration for investigations) are deferred until there is a
  concrete need to support them outside the terminal.

## Alternatives Considered

- **Build a web UI or dashboard first.** Rejected: significantly
  more upfront design and implementation cost, and less
  representative of how security engineers actually work
  day-to-day.
- **Build a library/SDK only, with no interface.** Rejected: would
  leave learners without a guided, interactive way to work through
  the lifecycle, undermining Duke's purpose as an education
  platform.
- **Build a TUI (e.g. with Textual) first.** Rejected for now: a
  plain CLI is simpler to implement, test, and document, and is a
  closer match to real-world security tooling; a TUI can be layered
  on top later if justified.
