"""Shared base class for Duke's core domain models."""

from pydantic import BaseModel, ConfigDict


class DukeModel(BaseModel):
    """Base class for all vendor-neutral core domain models.

    Unknown fields are rejected so that vendor- or tool-specific data
    cannot silently leak into the normalized core model; such data
    belongs in an adapter, translated into these models' own fields.
    """

    model_config = ConfigDict(extra="forbid")
