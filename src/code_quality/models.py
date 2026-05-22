"""Data models for code quality scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class QualityBand(str, Enum):
    POOR = "Poor"              # 0-30
    ACCEPTABLE = "Acceptable"  # 31-54
    ADEQUATE = "Adequate"      # 55-64
    GOOD = "Good"              # 65-79
    EXCELLENT = "Excellent"    # 80-100


@dataclass
class DimensionScore:
    """Score for a single quality dimension."""

    name: str
    score: float  # 0-100
    sub_scores: dict[str, float] = field(default_factory=dict)
    confidence: float = 1.0  # 0-1, lower when tools unavailable
    recommendations: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A single finding from an external tool."""

    rule_id: str
    severity: str
    confidence: str
    message: str
    file: str
    line: int
    tool: str


@dataclass
class ToolResult:
    """Result from running an external quality tool."""

    tool: str
    available: bool
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)
    error: str = ""

    @property
    def success(self) -> bool:
        return self.available and not self.error


@dataclass
class PQIResult:
    """Final PyQuality Index result."""

    composite: float  # 0-100
    dimensions: dict[str, DimensionScore] = field(default_factory=dict)
    quality_band: QualityBand = QualityBand.POOR
    floor_penalty: float = 1.0  # 1.0 = no penalty
    file_count: int = 0
    line_count: int = 0


WEIGHT_PROFILES: dict[str, dict[str, float]] = {
    "production": {
        "maintainability": 0.20,
        "security": 0.15,
        "modularity": 0.15,
        "testability": 0.15,
        "robustness": 0.13,
        "elegance": 0.12,
        "reusability": 0.10,
    },
    "library": {
        "maintainability": 0.15,
        "security": 0.10,
        "modularity": 0.20,
        "testability": 0.15,
        "robustness": 0.10,
        "elegance": 0.15,
        "reusability": 0.15,
    },
    "safety_critical": {
        "maintainability": 0.15,
        "security": 0.25,
        "modularity": 0.10,
        "testability": 0.20,
        "robustness": 0.15,
        "elegance": 0.05,
        "reusability": 0.10,
    },
}
