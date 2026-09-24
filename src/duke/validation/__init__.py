"""Detecting-rule validation over normalized telemetry.

Validation proves the detection → investigation → response-planning
pipeline behaves correctly by rerunning it against controlled, in-memory
mutations of a telemetry artefact. It never modifies the source artefact,
never writes files, never touches a network, and never executes a real
response action.
"""

from duke.validation.result import (
    ValidationCase,
    ValidationStatus,
    ValidationSuiteResult,
)
from duke.validation.t1078 import validate_t1078

__all__ = [
    "ValidationCase",
    "ValidationStatus",
    "ValidationSuiteResult",
    "validate_t1078",
]
