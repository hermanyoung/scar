"""SHA-256 evidence manifest for audit trail.

Append-only manifest that records hashes of all tool outputs
and LLM interactions for reproducibility verification.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, Field


class EvidenceEntry(BaseModel):
    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=0)
    source: str


class EvidenceManifest:
    """Append-only SHA-256 manifest for tool outputs and LLM responses."""

    def __init__(self):
        self._entries: list[EvidenceEntry] = []
        self._paths: set[str] = set()

    def record_file(self, path: Path | str, source: str) -> EvidenceEntry:
        """Compute SHA-256 of a file and add to the manifest."""
        path = Path(path)
        path_str = str(path)

        if path_str in self._paths:
            raise ValueError(f"Duplicate evidence path: {path_str}")

        content = path.read_bytes()
        entry = EvidenceEntry(
            path=path_str,
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            source=source,
        )

        self._entries.append(entry)
        self._paths.add(path_str)
        return entry

    def record_content(self, path: str, content: str | bytes, source: str) -> EvidenceEntry:
        """Compute SHA-256 of content and add to the manifest."""
        if path in self._paths:
            raise ValueError(f"Duplicate evidence path: {path}")

        if isinstance(content, str):
            content = content.encode("utf-8")

        entry = EvidenceEntry(
            path=path,
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            source=source,
        )

        self._entries.append(entry)
        self._paths.add(path)
        return entry

    def to_dict(self) -> list[dict]:
        return [e.model_dump() for e in self._entries]

    def __len__(self) -> int:
        return len(self._entries)
