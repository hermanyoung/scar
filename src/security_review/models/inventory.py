"""Inventory models for Pass 1: file discovery and weighting."""
from __future__ import annotations

from pydantic import BaseModel, Field


class FileEntry(BaseModel):
    """A single file in the review scope."""

    path: str = Field(min_length=1, description="Relative path from target root")
    language: str = Field(description="Detected language: python, csharp, config, other")
    size_bytes: int = Field(ge=0)
    security_weight: int = Field(
        ge=0,
        le=10,
        description="0=low interest, 10=highest security relevance",
    )
    estimated_tokens: int = Field(ge=0, description="Estimated token count for LLM batching")


class FileManifest(BaseModel):
    """Complete inventory of files in the review scope."""

    files: list[FileEntry] = []
    total_files: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    languages: dict[str, int] = Field(
        default_factory=dict,
        description="Language → file count",
    )


