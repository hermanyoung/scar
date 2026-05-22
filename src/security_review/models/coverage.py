"""Coverage model — tracks which detection layers cover which file types."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FileCoverage:
    """Coverage information for a single file type."""

    file_type: str
    file_count: int = 0
    deterministic_tools: list[str] = field(default_factory=list)
    semantic_passes: list[str] = field(default_factory=list)

    @property
    def coverage_level(self) -> str:
        has_det = len(self.deterministic_tools) > 0
        has_sem = len(self.semantic_passes) > 0
        if has_det and has_sem:
            return "strong"
        if has_det or has_sem:
            return "weak"
        return "none"

    @property
    def summary(self) -> str:
        parts = []
        if self.deterministic_tools:
            parts.extend(self.deterministic_tools)
        if self.semantic_passes:
            parts.extend(f"LLM {p}" for p in self.semantic_passes)
        if not parts:
            return "no coverage"
        label = " + ".join(parts)
        if self.coverage_level == "weak":
            label += " only"
        return label


@dataclass
class CoverageReport:
    """Aggregate coverage across all file types in a review."""

    by_type: dict[str, FileCoverage] = field(default_factory=dict)

    @property
    def weak_types(self) -> list[str]:
        return [ft for ft, cov in self.by_type.items() if cov.coverage_level == "weak"]

    @property
    def uncovered_types(self) -> list[str]:
        return [ft for ft, cov in self.by_type.items() if cov.coverage_level == "none"]
