"""Typed results produced by evidence-led investigations."""

from uuid import UUID

from pydantic import AwareDatetime, Field

from duke.core import Entity, Evidence, Finding
from duke.core._base import DukeModel


class TimelineEntry(DukeModel):
    """One event placed in an investigation timeline."""

    occurred_at: AwareDatetime
    event_id: UUID
    summary: str
    entity_ids: tuple[UUID, ...] = Field(default_factory=tuple)


class InvestigationResult(DukeModel):
    """Structured output of an evidence-led investigation."""

    finding: Finding
    involved_entities: tuple[Entity, ...]
    evidence: tuple[Evidence, ...]
    timeline: tuple[TimelineEntry, ...]
    confirmed_facts: tuple[str, ...]
    analyst_assessments: tuple[str, ...]
    unresolved_questions: tuple[str, ...]
