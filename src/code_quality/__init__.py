"""Code Quality — PyQuality Index (PQI) scoring engine.

Public API:
    score_project()  — Score a codebase's quality (main entry point)
    PQIResult        — Result with composite score + dimensions
    QualityBand      — Quality classification enum
"""
from code_quality.models import DimensionScore, PQIResult, QualityBand, WEIGHT_PROFILES
from code_quality.score import score_project
from code_quality.scoring import classify_band, compute_pqi

__all__ = [
    "score_project",
    "PQIResult",
    "QualityBand",
    "DimensionScore",
    "WEIGHT_PROFILES",
    "classify_band",
    "compute_pqi",
]
