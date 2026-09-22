"""Typed output produced by a Duke scenario simulation."""

from dataclasses import dataclass

from duke.core import Entity, Scenario, SecurityEvent


@dataclass(frozen=True, slots=True)
class SimulationResult:
    """A completed synthetic scenario simulation."""

    scenario: Scenario
    entities: tuple[Entity, ...]
    events: tuple[SecurityEvent, ...]

    def entity_by_identifier(self, identifier: str) -> Entity:
        """Return an entity using its stable natural identifier."""
        for entity in self.entities:
            if entity.identifier == identifier:
                return entity

        raise LookupError(f"Entity not found: {identifier}")
