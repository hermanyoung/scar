"""Finding priority scoring: Severity x Confidence x Exposure.

Produces a 0.0-1.0 composite priority score for each finding.
Sort descending = fix order.

Components:
  Severity  — how bad if exploited (from CWE/rule severity level)
  Confidence — how sure we are it's real (from triage or detection method)
  Exposure  — is the code reachable from external input (from inventory security weight)

Formula:
  priority = severity_score * confidence_score * exposure_score

The score is transparent and explainable: each component is visible
in the SARIF properties so reviewers understand why a finding is ranked
where it is.
"""
from __future__ import annotations

from dataclasses import dataclass

from security_review.models.findings import TriageVerdict
from security_review.models.inventory import FileManifest


# Severity: SARIF level -> numeric weight
_SEVERITY_SCORES: dict[str, float] = {
    "error": 1.0,     # CRITICAL / HIGH
    "warning": 0.6,   # MEDIUM
    "note": 0.3,      # LOW / INFORMATIONAL
    "none": 0.1,
}

# Confidence: how the finding was validated
_CONFIDENCE_SCORES: dict[str, float] = {
    "confirmed": 1.0,         # LLM triage confirmed — real vulnerability
    "sast+llm": 0.9,          # SAST found it, LLM confirmed
    "llm_only": 0.8,          # LLM holistic/config finding
    "sast_only": 0.7,          # Pattern match, no LLM validation
    "unvalidated": 0.6,        # No triage performed
    "needs_context": 0.5,      # LLM couldn't determine
    "false_positive": 0.0,     # LLM determined not exploitable — zero priority
}


@dataclass
class PriorityScore:
    """Composite priority score with transparent components."""

    priority: float          # 0.0 - 1.0 composite
    severity_score: float    # 0.1 - 1.0
    confidence_score: float  # 0.5 - 1.0
    exposure_score: float    # 0.1 - 1.0
    confidence_label: str    # e.g. "confirmed", "sast_only"

    @property
    def band(self) -> str:
        """Priority band — distinct from severity to avoid confusion.

        URGENT:   confirmed, exploitable, exposed — fix today
        ELEVATED: likely real, moderate exposure — fix this sprint
        MODERATE: possible issue, lower confidence — plan to fix
        LOW:      pattern match, unconfirmed, internal — backlog
        """
        if self.priority >= 0.7:
            return "URGENT"
        if self.priority >= 0.4:
            return "ELEVATED"
        if self.priority >= 0.2:
            return "MODERATE"
        return "LOW"


def score_finding(
    level: str,
    file_path: str,
    exposure_index: dict[str, float],
    triage_verdict: str | None = None,
    detection_method: str = "sast_only",
) -> PriorityScore:
    """Compute priority score for a single finding.

    Args:
        level: SARIF level (error, warning, note)
        file_path: File path of the finding (for exposure lookup)
        exposure_index: Pre-built file_path -> exposure score dict from build_exposure_index()
        triage_verdict: Triage result if available (CONFIRMED, FALSE_POSITIVE, NEEDS_CONTEXT)
        detection_method: How the finding was detected (sast_only, llm_only, sast+llm)
    """
    severity_score = _SEVERITY_SCORES.get(level.lower(), 0.3)

    if triage_verdict:
        verdict_lower = triage_verdict.lower()
        if verdict_lower == "confirmed":
            confidence_label = "confirmed"
        elif verdict_lower == "false_positive":
            confidence_label = "false_positive"
        elif verdict_lower == "needs_context":
            confidence_label = "needs_context"
        else:
            confidence_label = detection_method
    else:
        confidence_label = detection_method

    confidence_score = _CONFIDENCE_SCORES.get(confidence_label, 0.6)
    exposure_score = _lookup_exposure(file_path, exposure_index)
    priority = severity_score * confidence_score * exposure_score

    return PriorityScore(
        priority=round(priority, 3),
        severity_score=severity_score,
        confidence_score=confidence_score,
        exposure_score=exposure_score,
        confidence_label=confidence_label,
    )


def build_exposure_index(manifest: FileManifest | None) -> dict[str, float]:
    """Pre-build file_path -> exposure score lookup from manifest.

    Call once per merge pass, then pass the dict to score_finding.
    Avoids O(n*m) linear scan when scoring hundreds of findings.
    """
    if manifest is None:
        return {}
    return {
        entry.path: max(0.1, entry.security_weight / 10.0)
        for entry in manifest.files
    }


def _lookup_exposure(file_path: str, exposure_index: dict[str, float]) -> float:
    """Map file to exposure score via pre-built index."""
    return exposure_index.get(file_path, 0.3)
