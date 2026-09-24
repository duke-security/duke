"""Tests for the validation result models."""

import pytest
from pydantic import ValidationError

from duke.validation import (
    ValidationCase,
    ValidationStatus,
    ValidationSuiteResult,
)


def _case(status: ValidationStatus, name: str = "a-case") -> ValidationCase:
    return ValidationCase(
        name=name,
        expected="expected outcome",
        actual="actual outcome",
        status=status,
        explanation="why.",
    )


def test_all_passed_true_when_all_cases_pass() -> None:
    suite = ValidationSuiteResult(
        technique_id="T1078",
        cases=(
            _case(ValidationStatus.PASS),
            _case(ValidationStatus.PASS),
        ),
    )

    assert suite.all_passed is True


def test_all_passed_false_when_any_case_fails() -> None:
    suite = ValidationSuiteResult(
        technique_id="T1078",
        cases=(
            _case(ValidationStatus.PASS),
            _case(ValidationStatus.FAIL),
        ),
    )

    assert suite.all_passed is False


def test_all_passed_is_read_only() -> None:
    suite = ValidationSuiteResult(
        technique_id="T1078",
        cases=(_case(ValidationStatus.PASS),),
    )

    with pytest.raises(AttributeError):
        suite.all_passed = False  # type: ignore[misc]


def test_all_passed_reflects_case_set() -> None:
    failing = ValidationSuiteResult(
        technique_id="T1078",
        cases=(_case(ValidationStatus.FAIL),),
    )
    passing = ValidationSuiteResult(
        technique_id="T1078",
        cases=(_case(ValidationStatus.PASS),),
    )

    # all_passed is derived strictly from the contained case statuses.
    assert failing.all_passed is False
    assert passing.all_passed is True


def test_json_round_trip() -> None:
    suite = ValidationSuiteResult(
        technique_id="T1078",
        cases=(
            _case(ValidationStatus.PASS),
            _case(ValidationStatus.FAIL),
        ),
    )

    restored = ValidationSuiteResult.model_validate_json(suite.model_dump_json())

    assert restored == suite


def test_at_least_one_case_required() -> None:
    with pytest.raises(ValidationError):
        ValidationSuiteResult(technique_id="T1078", cases=())


def test_invalid_status_rejected() -> None:
    with pytest.raises(ValidationError):
        ValidationCase(
            name="x",
            expected="e",
            actual="a",
            status="maybe",
            explanation="why.",
        )


def test_unknown_field_rejected() -> None:
    with pytest.raises(ValidationError):
        ValidationCase(
            name="x",
            expected="e",
            actual="a",
            status=ValidationStatus.PASS,
            explanation="why.",
            extra=True,
        )
