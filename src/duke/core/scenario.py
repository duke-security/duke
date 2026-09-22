"""Scenario: metadata describing a guided, end-to-end learning scenario."""

from datetime import date
from uuid import UUID, uuid4

from pydantic import Field

from duke.core._base import DukeModel


class Scenario(DukeModel):
    """Metadata describing a single guided learning scenario.

    A scenario is metadata, not code: it describes what a scenario
    teaches and requires so that scenario simulation, detection, and
    labs can be built and reviewed against a clear specification. It
    does not embed simulation, detection, or response logic itself.
    """

    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    attack_technique_id: str = Field(
        description="MITRE ATT&CK technique identifier, e.g. 'T1078'.",
    )
    attack_tactics: list[str] = Field(
        min_length=1,
        description=(
            "MITRE ATT&CK tactic names associated with the technique, "
            "e.g. 'Initial Access' or 'Defense Evasion'."
        ),
    )
    learning_objectives: list[str] = Field(
        min_length=1,
        description="What a learner should understand after completing this scenario.",
    )
    python_concepts: list[str] = Field(
        min_length=1,
        description="Python concepts this scenario is designed to teach or exercise.",
    )
    telemetry_requirements: list[str] = Field(
        default_factory=list,
        description="Normalized telemetry this scenario must generate or consume.",
    )
    safety_notes: list[str] = Field(
        min_length=1,
        description="Safety boundaries and what this scenario does not implement.",
    )
    version: str = Field(description="Version of this scenario's definition.")
    last_reviewed: date = Field(description="Date this scenario was last reviewed.")
