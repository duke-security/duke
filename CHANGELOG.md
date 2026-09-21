# Changelog

All notable changes to Duke are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Duke adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Documentation foundation: README, ROADMAP, CONTRIBUTING, and
  architecture/development documentation describing Duke's current
  capabilities and planned components.
- Architecture Decision Records for a vendor-agnostic core
  (ADR 0001), a CLI-first interface (ADR 0002), and safe synthetic
  simulations (ADR 0003).
- Installable Python package (`duke-security`) with a Typer/Rich
  command-line interface.
- `duke --help` and `duke version` commands.
- CLI unit tests.
- Ruff, mypy (strict), and pytest quality gates.
