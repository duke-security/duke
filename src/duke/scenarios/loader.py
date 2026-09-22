"""Load and validate packaged Duke scenario definitions."""

from importlib.resources import files
from typing import Any

import yaml
from pydantic import ValidationError
from yaml import YAMLError

from duke.core import Scenario


class ScenarioLoadError(ValueError):
    """Raised when a scenario definition cannot be loaded or validated."""


def load_builtin_scenario(slug: str) -> Scenario:
    """Load a packaged scenario by its directory slug."""
    if not slug or not all(part.isalnum() for part in slug.split("_")):
        raise ScenarioLoadError(f"Invalid scenario slug: {slug!r}")

    resource = files("duke.scenarios").joinpath(slug, "scenario.yaml")

    if not resource.is_file():
        raise ScenarioLoadError(f"Scenario not found: {slug}")

    try:
        raw_data: Any = yaml.safe_load(resource.read_text(encoding="utf-8"))
        return Scenario.model_validate(raw_data)
    except (OSError, YAMLError, ValidationError) as exc:
        raise ScenarioLoadError(
            f"Could not load scenario {slug!r}: {exc}",
        ) from exc
