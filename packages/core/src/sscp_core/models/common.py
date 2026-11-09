"""Base model and small value objects shared by the other model modules."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Base(BaseModel):
    """Base class for every domain model.

    Frozen, because the pipeline builds new objects rather than mutating shared
    ones; that is what keeps a scan reproducible. Sequence fields are tuples
    for the same reason. ``extra="forbid"`` turns a typo in an upstream payload
    into an error at the boundary instead of a silently dropped field.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        populate_by_name=True,
        validate_assignment=True,
        str_strip_whitespace=True,
    )


class CvssScore(Base):
    """A CVSS vector and its base score."""

    version: Literal["2.0", "3.0", "3.1", "4.0"]
    vector: str
    base_score: float = Field(ge=0.0, le=10.0)


class Reference(Base):
    """An advisory reference, using the OSV reference vocabulary."""

    type: str
    url: str


class FileHash(Base):
    """A content hash, named as CycloneDX names them."""

    alg: str
    content: str


__all__ = ["Base", "CvssScore", "FileHash", "Reference"]
