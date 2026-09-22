"""Export simulation results as structured JSON artefacts."""

import json
from pathlib import Path
from typing import Any

from duke.simulation.result import SimulationResult


def simulation_payload(result: SimulationResult) -> dict[str, Any]:
    """Convert a simulation result into a JSON-compatible payload."""
    return {
        "schema_version": "1.0",
        "scenario": result.scenario.model_dump(mode="json"),
        "entities": [
            entity.model_dump(mode="json")
            for entity in result.entities
        ],
        "events": [
            event.model_dump(mode="json")
            for event in result.events
        ],
    }


def export_simulation(
    result: SimulationResult,
    output_path: Path,
    *,
    overwrite: bool = False,
) -> Path:
    """Write a simulation artefact without silently overwriting files."""
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {output_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = simulation_payload(result)

    output_path.write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )

    return output_path
