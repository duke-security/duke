"""Typed results describing a detection-rule validation suite.

Validation runs the detection → investigation → response pipeline
against controlled, in-memory mutations of a telemetry artefact and
records, for each case, its expected outcome, the actual outcome, and
whether they agree. :class:`ValidationSuiteResult.all_passed` is a
derived, read-only property so a caller can never construct a suite whose
``all_passed`` flag disagrees with its contained cases.
"""

from enum import StrEnum

from pydantic import Field

from duke.core._base import DukeModel


class ValidationStatus(StrEnum):
    """Whether a single validation case matched its expected outcome."""

    PASS = "pass"
    FAIL = "fail"


class ValidationCase(DukeModel):
    """One validation case: a mutation, its expected outcome, and the result."""

    name: str
    expected: str = Field(
        description="The expected outcome for this case, human readable.",
    )
    actual: str = Field(
        description="The actual outcome observed, human readable.",
    )
    status: ValidationStatus
    explanation: str = Field(
        description="Why this case passed or failed.",
    )


class ValidationSuiteResult(DukeModel):
    """The outcome of validating a technique's detection pipeline."""

    technique_id: str = Field(
        description="MITRE ATT&CK technique identifier, e.g. 'T1078'.",
    )
    cases: tuple[ValidationCase, ...] = Field(
        min_length=1,
        description="Every validation case, in definition order.",
    )

    @property
    def all_passed(self) -> bool:
        """Whether every contained case has PASS status.

        Read-only and always derived from ``cases``, so it can never be
        constructed inconsistently with the cases themselves.
        """
        return all(case.status is ValidationStatus.PASS for case in self.cases)
